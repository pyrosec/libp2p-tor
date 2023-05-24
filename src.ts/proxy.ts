import type { Libp2pOptions } from "libp2p";
import { Libp2pWrapped } from "./libp2p.wrapper";
import type { BaseMessageHandler } from "./libp2p.wrapper";
import { generateEphemeralKeyPair } from "@libp2p/crypto/keys";
import type { ECDHKey } from "@libp2p/crypto/keys/interface";
import { pipe } from "it-pipe";
import { encode, decode } from "it-length-prefixed";
import { Multiaddr, multiaddr } from "@multiformats/multiaddr";
import {
  Cell,
  CellCommand,
  RelayCell,
  RelayCellCommand,
  PROTOCOLS,
} from "./tor";
import { StreamHandler } from "@libp2p/interface-registrar";
import { fromString, equals, toString } from "uint8arrays";
import * as crypto from "@libp2p/crypto";
import type { PrivateKey } from "@libp2p/interface-keys";
import { iv } from "./constants";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { protocol } from "./protocol";

const createHmac = crypto.hmac.create;

export class Proxy extends Libp2pWrapped {
  private torKey: PrivateKey;
  public registries: Multiaddr[];
  private keys: Record<
    number,
    {
      sharedKey: Uint8Array;
      key: ECDHKey;
      aes: crypto.aes.AESCipher;
      publicKey: Uint8Array;
      hmac: Awaited<ReturnType<typeof createHmac>>;
      nextHop: {
        multiaddr: Multiaddr;
        circuitId: number;
      };
      prevHop: {
        multiaddr: Multiaddr;
        circuitId: number;
      };
    }
  >;
  private active: Record<number, Multiaddr>;

  constructor(registries: Multiaddr[]) {
    super();
    this.registries = registries;
    this.keys = {};
    this.torKey = null;
    this.active = {};
  }

  async run(
    options: Libp2pOptions = {
      addresses: {
        listen: ["/ip4/127.0.0.1/tcp/0"],
      },
    }
  ) {
    this.baseMessageHandlers["rendezvous/cookie"] =
      this.handleBaseMessageRendezvousCookie;
    this.baseMessageHandlers["rendezvous/begin"] =
      this.handleBaseMessageRendezvousBegin;
    await super.run(options);
    this.torKey = await crypto.keys.generateKeyPair("RSA", 1024);
    await this.register();
    await this.handle(PROTOCOLS.message, this.handleTorMessage);
    await this.handle(PROTOCOLS.advertise, this.handleAdvertise);
  }

  handleBaseMessageRendezvousBegin: BaseMessageHandler = async ({
    stream,
    baseMessage,
  }) => {
    console.log(toString(baseMessage.content), baseMessage.content);
    const cookie = await this.waitForResponseOnChannel(
      toString(baseMessage.content)
    );
    await this.sendTorCell({
      stream,
      data: protocol.BaseMessage.encode({
        type: "rendezvous/cookie/receive",
        content: cookie,
      }),
    });
  };
  handleBaseMessageRendezvousCookie: BaseMessageHandler = async ({
    stream,
    baseMessage,
  }) => {
    const encryptedContent = baseMessage.content.slice(0, 256);
    const pubKey = baseMessage.content.slice(256);
    console.log("received cookie");
    console.log(toString(pubKey), pubKey);
    this.sendMessageToResponseChannel(toString(pubKey), encryptedContent);
    //TODO: ping pubkey circuit
    await this.sendTorCell({
      stream,
      data: protocol.BaseMessage.encode({
        type: "string",
        content: fromString("SUCCESS"),
      }).finish(),
    });
  };

  handleAdvertise: StreamHandler = async ({ stream }) => {
    const pubKey = await pipe(stream.source, decode(), async (source) => {
      let _pubKey: Uint8Array;
      for await (const data of source) {
        _pubKey = data.subarray();
      }
      return _pubKey;
    });
    const hash = await sha256.digest(pubKey);
    const cid = CID.create(1, 0x01, hash);
    //TODO: store pubkey with cid
    await this._libp2p.contentRouting.provide(cid);
  };

  handleTorMessage: StreamHandler = async ({ stream, connection }) => {
    console.log("handling tor message");
    await pipe(stream.source, decode(), async (source) => {
      let ret: Uint8Array;
      for await (const data of source) {
        ret = data.subarray();
        const cell = Cell.decode(ret);
        let returnCell: any,
          shouldBreak: boolean = false;
        if (cell.command == CellCommand.CREATE) {
          shouldBreak = true;
          const cellData: Uint8Array = Uint8Array.from(
            //@ts-ignore
            await this.torKey.decrypt((cell.data as Uint8Array).slice(0, 128))
          );
          returnCell = protocol.Cell.encode({
            circuitId: cell.circuitId,
            command: CellCommand.CREATED,
            data: await this.handleCreateCell(
              cell.circuitId,
              cellData,
              connection.remoteAddr
            ),
          }).finish();
        } else if (cell.command == CellCommand.RELAY) {
          const aes = this.keys[`${cell.circuitId}`].aes;
          const nextHop = this.keys[`${cell.circuitId}`].nextHop;
          if (nextHop == undefined) {
            returnCell = (
              await this.handleRelayCell({
                circuitId: cell.circuitId,
                relayCell: RelayCell.from(
                  await aes.decrypt(cell.data as Uint8Array)
                ),
              })
            ).encode();
          } else {
            const nextCellEncoded = await this.sendTorCellWithResponse({
              peerId: nextHop.multiaddr,
              protocol: PROTOCOLS.message,
              data: protocol.Cell.encode({
                circuitId: nextHop.circuitId,
                data: await aes.decrypt(cell.data as Uint8Array),
                command: CellCommand.RELAY,
              }).finish(),
            });
            const nextCell = Cell.decode(nextCellEncoded);
            returnCell = protocol.Cell.encode({
              command: CellCommand.RELAY,
              circuitId: cell.circuitId,
              data: await aes.encrypt(nextCell.data as Uint8Array),
            }).finish();
          }
        }
        await this.sendTorCell({
          stream,
          data: returnCell,
        });
        if (shouldBreak) break;
      }
    });
  };

  async handleRelayCell({
    circuitId,
    relayCell,
  }: {
    circuitId: number;
    relayCell: RelayCell;
  }) {
    const { hmac } = this.keys[`${circuitId}`];
    const relayCellData = relayCell.data.subarray(0, relayCell.len);
    const hash = await hmac.digest(relayCellData);
    if (!equals(Uint8Array.from(hash.subarray(0, 6)), relayCell.digest))
      throw new Error("digest does not match");
    if (relayCell.command == RelayCellCommand.EXTEND) {
      return await this.handleRelayExtend({ circuitId, relayCellData });
    }
    if (relayCell.command == RelayCellCommand.BEGIN) {
      return await this.handleRelayBegin({ circuitId, relayCellData });
    }
    if (relayCell.command == RelayCellCommand.DATA) {
      return await this.handleRelayData({ circuitId, relayCellData });
    }
  }
  async handleRelayData({
    circuitId,
    relayCellData,
  }: {
    circuitId: number;
    relayCellData: Uint8Array;
  }) {
    const { aes, hmac } = this.keys[`${circuitId}`];
    if (this.active[circuitId]) {
      const stream = await this.dialProtocol(
        this.active[circuitId],
        PROTOCOLS.baseMessage
      );
      pipe([relayCellData], encode(), stream.sink);
      const returnData = await pipe(stream.source, decode(), async (source) => {
        let _d: Uint8Array;
        for await (const data of source) {
          _d = data.subarray();
        }
        return _d;
      });
      return new Cell({
        command: CellCommand.RELAY,
        data: await aes.encrypt(
          new RelayCell({
            streamId: circuitId,
            data: returnData,
            len: returnData.length,
            digest: await hmac.digest(returnData),
            command: RelayCellCommand.DATA,
          }).encode()
        ),
        circuitId,
      });
    }
    return new Cell({
      command: CellCommand.RELAY,
      circuitId,
      data: await aes.encrypt(
        new RelayCell({
          command: RelayCellCommand.END,
          data: fromString(""),
          len: 0,
          digest: await hmac.digest(fromString("")),
          streamId: circuitId,
        }).encode()
      ),
    });
  }
  async handleRelayBegin({
    circuitId,
    relayCellData,
  }: {
    circuitId: number;
    relayCellData: Uint8Array;
  }) {
    //change this so that the stream is kept active throughout the relay
    const { aes, hmac } = this.keys[`${circuitId}`];
    console.log("handling begin");
    const addr = multiaddr(relayCellData.slice(0, relayCellData.length));
    const returnData = protocol.BaseMessage.decode(
      await this.sendTorCellWithResponse({
        peerId: addr,
        protocol: PROTOCOLS.baseMessage,
        data: protocol.BaseMessage.encode({
          type: "string",
          content: fromString("BEGIN"),
        }).finish(),
      })
    );
    let content: any;
    switch (returnData.type) {
      default:
        content = toString(returnData.content);
    }
    const data = fromString("BEGUN");
    if (content == "BEGUN") {
      this.active[circuitId] = addr;
      return new Cell({
        command: CellCommand.RELAY,
        data: await aes.encrypt(
          new RelayCell({
            command: RelayCellCommand.CONNECTED,
            data,
            streamId: circuitId,
            digest: await hmac.digest(data),
            len: data.length,
          }).encode()
        ),
        circuitId,
      });
    } else {
      return new Cell({
        command: CellCommand.RELAY,
        data: await aes.encrypt(
          new RelayCell({
            command: RelayCellCommand.END,
            data,
            streamId: circuitId,
            digest: await hmac.digest(data),
            len: data.length,
          }).encode()
        ),
        circuitId,
      });
    }
  }
  async handleRelayExtend({
    circuitId,
    relayCellData,
  }: {
    circuitId: number;
    relayCellData: Uint8Array;
  }) {
    const { aes, hmac } = this.keys[`${circuitId}`];
    const encryptedKey = relayCellData.slice(0, 128);
    const multiAddr = multiaddr(relayCellData.slice(128));
    const hop = (this.keys[`${circuitId}`].nextHop = {
      multiaddr: multiAddr,
      circuitId: Buffer.from(crypto.randomBytes(16)).readUint16BE(),
    });
    const returnData = Cell.decode(
      await this.sendTorCellWithResponse({
        peerId: multiAddr,
        protocol: PROTOCOLS.message,
        data: new Cell({
          command: CellCommand.CREATE,
          data: encryptedKey,
          circuitId: hop.circuitId,
        }).encode(),
      })
    );
    if (returnData.command !== CellCommand.CREATED) {
      return new Cell({
        circuitId,
        command: CellCommand.RELAY,
        data: await aes.encrypt(
          new RelayCell({
            data: Uint8Array.from([]),
            command: RelayCellCommand.END,
            streamId: circuitId,
            len: 0,
            digest: Uint8Array.from([]),
          }).encode()
        ),
      });
    }
    const returnDigest = await hmac.digest(returnData.data as Uint8Array);
    return new Cell({
      circuitId,
      command: CellCommand.RELAY,
      data: await aes.encrypt(
        new RelayCell({
          data: returnData.data as Uint8Array,
          command: RelayCellCommand.EXTENDED,
          streamId: circuitId,
          len: 65 + 32,
          digest: returnDigest,
        }).encode()
      ),
    });
  }

  async handleCreateCell(
    circuitId: number,
    cellData: Uint8Array,
    prevHop: Multiaddr
  ) {
    const ecdhKey = await generateEphemeralKeyPair("P-256");
    const sharedKey = await ecdhKey.genSharedKey(cellData);
    const hmac = await createHmac("SHA256", sharedKey);
    this.keys[`${circuitId}`] = {
      sharedKey,
      key: ecdhKey,
      aes: await crypto.aes.create(sharedKey, iv),
      publicKey: cellData,
      hmac,
      nextHop: undefined,
      prevHop: {
        circuitId,
        multiaddr: prevHop,
      },
    };

    const digest = await hmac.digest(sharedKey);
    const data = new Uint8Array(digest.length + ecdhKey.key.length);
    data.set(ecdhKey.key);
    data.set(digest, ecdhKey.key.length);
    return data;
  }

  async register() {
    await this.registries.reduce<any>(async (_a, registry) => {
      try {
        const stream = await this.dialProtocol(registry, PROTOCOLS.register);
        pipe(
          [
            fromString(
              JSON.stringify({
                key: this.torKey.public.marshal(),
                addr: this._libp2p.getMultiaddrs()[0].toString(),
              })
            ),
          ],
          encode(),
          stream.sink
        );
        await pipe(stream.source, decode(), async (source) => {
          for await (const data of source) {
            if (data.subarray()[0] != 1) throw new Error();
          }
        });
      } catch (e) {
        console.log(e);
      }
    }, Promise.resolve());
  }

  key() {
    return this.torKey.public.marshal();
  }
}
