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

interface HandleTorCellInput {
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

export type BaseMessageHandler = ({
  stream,
  baseMessage,
}: {
  stream: Stream;
  baseMessage: { content: any; type: string };
}) => Promise<void>;

export class Libp2pWrapped extends EventEmitter {
  public _libp2p: Libp2p;
  public baseMessageHandlers: Record<string, BaseMessageHandler>;

  constructor(opts?: any) {
    super(opts);
    this.baseMessageHandlers = {};
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
    return await new Promise((resolve, reject) => {
      pipe(stream.source, decode(), async (source) => {
        try {
          resolve((await (source[Symbol.iterator]()).next()).value.subarray());
	} catch (e) {
          reject(e);
	}
      });
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
    if ("finish" in input && input.finish === true) {
      messages.end();
    }
    return { stream, messages };
  }

  handleBaseMessageString: BaseMessageHandler = async ({
    stream,
    baseMessage,
  }) => {
    let content = toString(baseMessage["content"]);
    console.log(content);
    if (content == "BEGIN") {
      await this.sendTorCell({
        stream,
        data: protocol.BaseMessage.encode({
          type: "string",
          content: fromString("BEGUN"),
        }).finish(),
      });
    }
  };

  handleBaseMessage: StreamHandler = async ({ stream }) => {
    console.log("handling base message");
    await pipe(stream.source, decode(), async (source) => {
      for await (const _data of source) {
        const data = _data.subarray();
        const baseMessage = protocol.BaseMessage.decode(data);
        console.log(baseMessage["type"]);
        if (baseMessage["type"] in this.baseMessageHandlers) {
          await this.baseMessageHandlers[baseMessage["type"]]({
            stream,
            baseMessage,
          });
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
    let endNow = false,
      end = () => {
        endNow = true;
      };
    pipe(stream.source, decode(), async (source) => {
      for await (const data of source) {
        console.log("received data");
        if (endNow) break;
        const res = await handler(data.subarray(), stream);
        if (res === false) break;
      }
    });
    return { end };
  }

  sendMessageToChannel(channel: string, message: Uint8Array) {
    this.emit(`${channel}:message`, message);
  }
  sendMessageToResponseChannel(channel: string, message: any) {
    this.emit(`${channel}:response`, message);
  }
}
