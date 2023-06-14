import type { Libp2p, Libp2pOptions } from "libp2p";
import { createLibp2p } from "libp2p";
import { TCP } from "@libp2p/tcp";
import { KadDHT } from "@libp2p/kad-dht";
import { mplex } from "@libp2p/mplex";
import { Noise } from "@chainsafe/libp2p-noise";
import { EventEmitter } from "node:events";
import type { StreamHandler } from "@libp2p/interface-registrar";
import type { Stream } from "@libp2p/interface-connection";
import { PeerId } from "@libp2p/interface-peer-id";
import { Multiaddr } from "@multiformats/multiaddr";
import { pushable, Pushable } from "it-pushable";
import { encode, decode } from "it-length-prefixed";
import { pipe } from "it-pipe";
import { PROTOCOLS } from "./tor";
import { fromString, toString } from "uint8arrays";
import { protocol } from "./protocol";

type SendTorCellInput = {
  peerId: Multiaddr | PeerId;
  protocol: string;
  data: any;
  finish?: boolean;
};

type SendTorCellInputWithStream = {
  stream: Stream;
  data: Uint8Array;
};
type PushTorCellInput = {
  messages: Pushable<any>;
  data: Uint8Array;
};

interface ActiveBaseMessages {
  messages: Pushable<any>;
  stream: Stream;
}

export async function createLibp2pNode(
  options: Libp2pOptions
): Promise<Libp2p> {
  options.transports = [new TCP()];
  //@ts-ignore
  options.connectionEncryption = [new Noise()];
  //@ts-ignore
  options.streamMuxers = [mplex()()];
  //@ts-ignore
  options.dht = new KadDHT();

  return await createLibp2p(options);
}

export type BaseMessageHandler = (
  baseMessage: {
    content: any;
    type: string;
    circuitId: number;
  },
  circuitId?: number
) => Promise<any>;

export class Libp2pWrapped extends EventEmitter {
  public _libp2p: Libp2p;
  public baseMessageHandlers: Record<string, BaseMessageHandler>;
  public activeBaseMessages: Record<number, ActiveBaseMessages>;
  public type: string;

  constructor(opts?: any) {
    super(opts);
    this.baseMessageHandlers = {};
    this.activeBaseMessages = {};
  }

  async run(options: Libp2pOptions) {
    this._libp2p = await createLibp2pNode(options);
    this.baseMessageHandlers["string"] = this.handleBaseMessageString;
    await this._libp2p.start();
    await this.handle(PROTOCOLS.baseMessage, this.handleBaseMessage);
  }
  handle(protocol: string, handler: StreamHandler, options = {}) {
    return this._libp2p.handle(protocol, handler, options);
  }
  dialProtocol(peerId: Multiaddr | PeerId, protocol: string, options = {}) {
    //@ts-ignore
    return this._libp2p.dialProtocol(peerId, protocol, options);
  }

  // pipes to protocol and expects a response
  async sendTorCellWithResponse(
    input: SendTorCellInput | SendTorCellInputWithStream
  ) {
    const { stream } = await this.sendTorCell(input);
    return this.waitForSingularResponse(stream);
  }

  async waitForSingularResponse(stream: Stream) {
    return await new Promise(async (resolve, reject) => {
      const source = pipe(stream.source, decode());
      const d = await source[Symbol.asyncIterator]().next();
      resolve(d.value.subarray());
    });
  }
  async pushTorCell(input: PushTorCellInput) {
    input.messages.push(input.data);
  }
  async sendTorCell(input: SendTorCellInput | SendTorCellInputWithStream) {
    const messages = pushable();
    let stream: Stream;
    if ("stream" in input) {
      stream = input.stream;
    } else {
      stream = await this.dialProtocol(input.peerId, input.protocol);
    }
    pipe(messages, encode(), stream.sink);
    messages.push(input.data);
    return { stream, messages };
  }

  handleBaseMessageString: BaseMessageHandler = async (baseMessage) => {
    let content = toString(baseMessage["content"]);

    console.log(content);
    if (content == "BEGIN") {
      console.log(baseMessage.circuitId);
      return protocol.BaseMessage.encode({
        type: "string",
        content: fromString("BEGUN"),
        circuitId: baseMessage.circuitId,
      }).finish();
    }
    if (content == "BEGUN") {
      this.emit("begin:response", baseMessage.circuitId);
    }
    return false;
  };

  handleBaseMessage: StreamHandler = async ({ stream }) => {
    console.log("handling base message");
    pipe(stream.source, decode(), async (source) => {
      for await (const _data of source) {
        const data = _data.subarray();
        const baseMessage = protocol.BaseMessage.decode(data);
        if (baseMessage["type"] in this.baseMessageHandlers) {
          const returnData = await this.baseMessageHandlers[
            baseMessage["type"]
          ](baseMessage);
          if (returnData !== false) {
            if (!this.activeBaseMessages[baseMessage.circuitId]) {
              const { messages } = await this.sendTorCell({
                stream,
                data: returnData,
              });
              this.activeBaseMessages[Number(baseMessage.circuitId)] = {
                stream,
                messages,
              };
            } else
              this.activeBaseMessages[
                Number(baseMessage.circuitId)
              ].messages.push(returnData);
          }
        }
      }
    });
  };

  waitForResponseOnChannel(channel: string): Promise<Uint8Array> {
    return new Promise((resolve) => {
      this.on(`${channel}:response`, (data: Uint8Array) => {
        resolve(data);
      });
    });
  }

  handleResponsesOnChannel({
    stream,
    handler,
  }: {
    stream: Stream;
    handler: (data: Uint8Array, stream: Stream) => Promise<any>;
  }) {
    pipe(stream.source, decode(), async (source) => {
      for await (const data of source) {
        console.log("received data");
        const res = await handler(data.subarray(), stream);
        if (res === false) break;
      }
    });
  }

  sendMessageToChannel(channel: string, message: Uint8Array) {
    this.emit(`${channel}:message`, message);
  }
  sendMessageToResponseChannel(channel: string, message: any) {
    this.emit(`${channel}:response`, message);
  }
}
