import type { Libp2p, Libp2pOptions } from "libp2p";
import { createLibp2p } from "libp2p";
import { TCP } from "@libp2p/tcp";
import { KadDHT } from "@libp2p/kad-dht";
import { mplex } from "@libp2p/mplex";
import { Noise } from "@chainsafe/libp2p-noise";
import { EventEmitter } from "node:events";
import type { StreamHandler } from "@libp2p/interface-registrar";
import { PeerId } from "@libp2p/interface-peer-id";
import { Multiaddr } from "@multiformats/multiaddr";
import { pushable } from "it-pushable";
import { encode, decode } from "it-length-prefixed";
import { pipe } from "it-pipe";

interface PipeToInput {
  peerId: Multiaddr | PeerId;
  protocol: string;
  data: Uint8Array;
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

export class Libp2pWrapped extends EventEmitter {
  public _libp2p: Libp2p;
  async run(options: Libp2pOptions) {
    this._libp2p = await createLibp2pNode(options);
    await this._libp2p.start();
  }
  handle(protocol: string, handler: StreamHandler, options = {}) {
    return this._libp2p.handle(protocol, handler, options);
  }
  dialProtocol(peerId: Multiaddr | PeerId, protocol: string, options = {}) {
    //@ts-ignore
    return this._libp2p.dialProtocol(peerId, protocol, options);
  }

  // pipes to protocol and expects a response
  async pipeTo(input: PipeToInput) {
    const messages = pushable();
    const stream = await this.dialProtocol(input.peerId, input.protocol);

    pipe(messages, encode(), stream.sink);
    messages.push(input.data).end();

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
}
