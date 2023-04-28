import { StreamHandler } from "@libp2p/interface-registrar";
import { Libp2pOptions } from "libp2p";
import { Libp2pWrapped } from "./libp2p.wrapper";
import { fromString, toString } from "uint8arrays";
import { encode, decode } from "it-length-prefixed";
import { pipe } from "it-pipe";

export class Registry extends Libp2pWrapped {
  private relays: Record<string, any> = {};
  unregister: StreamHandler = async ({ connection }) => {
    delete this.relays[connection.remotePeer.toString()];
  };

  listRelays: StreamHandler = async ({ stream }) => {
    console.log("handling list");
    const keys = JSON.stringify(
      Object.entries(this.relays).map(([id, data]) => ({
        id,
        ...data,
      }))
    );
    pipe([fromString(keys)], encode(), stream.sink);
  };

  register: StreamHandler = async ({ connection, stream }) => {
    console.log("data received");
    const peerData = await pipe(stream.source, decode(), async (source) => {
      let str = "";
      for await (let data of source) {
        str += toString(data.subarray());
      }
      return JSON.parse(str);
    });
    this.relays[connection.remotePeer.toString()] = {
      publicKey: new Uint8Array(Object.values(peerData.key)),
      addr: peerData.addr,
    };
    pipe([Uint8Array.from([1])], encode(), stream.sink);
  };
  run = async (
    options: Libp2pOptions = {
      addresses: {
        listen: ["/ip4/127.0.0.1/tcp/5000"],
      },
    }
  ) => {
    await super.run(options);

    console.log("running node");
    await this.handle("/tor/1.0.0/register", this.register);
    await this.handle("/tor/1.0.0/unregister", this.unregister);
    await this.handle("/tor/1.0.0/relays", this.listRelays);
  };
}
