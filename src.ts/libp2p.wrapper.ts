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
import { pushable } from "it-pushable";
import { encode, decode } from "it-length-prefixed";
import { pipe } from "it-pipe";
import { PROTOCOLS } from "./tor";
import { fromString, toString } from "uint8arrays";
import { protocol } from "./protocol";

type SendTorCellInput = {
  peerId: Multiaddr | PeerId;
  protocol: string;
  data: any;
};

type SendTorCellInputWithStream = {
  stream: Stream;
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

type BaseMessageHandler = ({
  stream,
  baseMessage,
}: {
  stream: Stream;
  baseMessage: { content: any; type: string };
}) => Promise<void>;

export class Libp2pWrapped extends EventEmitter {
  public _libp2p: Libp2p;
  public baseMessageHandlers: Record<string, BaseMessageHandler>;

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
    const stream = await this.sendTorCell(input);

    return await pipe(stream.source, decode(), async (source) => {
      let ret: Uint8Array;
      // breaks on first iteration
      for await (const data of source) {
        ret = data.subarray();
        break;
      }
      return ret;
    });
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
    messages.push(input.data).end();
    return stream;
  }

  handleBaseMessageString: BaseMessageHandler = async ({
    stream,
    baseMessage,
  }) => {
    let content = toString(baseMessage["content"]);

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
    const data = await pipe(stream.source, decode(), async (source) => {
      let _ret: Uint8Array;
      for await (const _data of source) {
        _ret = _data.subarray();
        break;
      }
      return _ret;
    });
    const baseMessage = protocol.BaseMessage.decode(data);
    if (baseMessage["type"] in this.baseMessageHandlers) {
      await this.baseMessageHandlers[baseMessage["type"]]({
        stream,
        baseMessage,
      });
    }
  };
}
