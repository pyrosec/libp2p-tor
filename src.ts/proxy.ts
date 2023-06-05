import type { Libp2pOptions } from "libp2p";
import { Libp2pWrapped } from "./libp2p.wrapper";
import type { BaseMessageHandler } from "./libp2p.wrapper";
import { generateEphemeralKeyPair } from "@libp2p/crypto/keys";
import type { ECDHKey } from "@libp2p/crypto/keys/interface";
import { pipe } from "it-pipe";
import type { Pushable } from "it-pushable";
import { encode, decode } from "it-length-prefixed";
import { Multiaddr, multiaddr } from "@multiformats/multiaddr";
import {
  Cell,
  CellCommand,
  RelayCell,
  RelayCellCommand,
  PROTOCOLS,
} from "./tor";
import type { Stream } from "@libp2p/interface-connection";
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
  private active: Record<
    number,
    {
      addr: Multiaddr;
      messages?: Pushable<any>;
      stream?: Stream;
      end?: any;
      prevMessages?: Pushable<any>;
      prevStream?: Stream;
    }
  >;

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
    const cookie = await this.waitForResponseOnChannel(
      toString(baseMessage.content)
    );
    console.log("cookie", cookie);
    await this.sendTorCell({
      stream,
      data: protocol.BaseMessage.encode({
        type: "rendezvous/cookie/receive",
        content: cookie,
      }).finish(),
    });
  };
  handleBaseMessageRendezvousCookie: BaseMessageHandler = async ({
    stream,
    baseMessage,
  }) => {
    const encryptedContent = baseMessage.content.slice(0, 256);
    const pubKey = baseMessage.content.slice(256);
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
    await pipe(stream.source, decode(), async (source) => {
      let ret: Uint8Array;
      for await (const data of source) {
        console.log("handling tor message");
        ret = data.subarray();
        const cell = Cell.decode(ret);
        console.log(cell.command);
        let returnCell: any;
        if (cell.command == CellCommand.CREATE) {
          const cellData: Uint8Array = Uint8Array.from(
            //@ts-ignore
            await this.torKey.decrypt((cell.data as Uint8Array).slice(0, 128))
          );
          returnCell = new Cell({
            circuitId: cell.circuitId,
            command: CellCommand.CREATED,
            data: await this.handleCreateCell(
              cell.circuitId,
              cellData,
              connection.remoteAddr
            ),
          }).encode();
          const { messages } = await this.sendTorCell({
            stream,
            data: returnCell,
          });
          //@ts-ignore
          this.active[cell.circuitId] = {
            prevMessages: messages,
            prevStream: stream,
          };
        } else if (cell.command == CellCommand.RELAY) {
          const aes = this.keys[`${cell.circuitId}`].aes;
          const nextHop = this.keys[`${cell.circuitId}`].nextHop;
          if (nextHop == undefined) {
            returnCell = await this.handleRelayCell({
              circuitId: cell.circuitId,
              relayCell: RelayCell.from(
                await aes.decrypt(cell.data as Uint8Array)
              ),
              stream,
            });
            if (returnCell) {
              if (!this.active[cell.circuitId].prevMessages) {
                const { messages: _messages } = await this.sendTorCell({
                  stream,
                  data: returnCell.encode(),
                });

                this.active[cell.circuitId] = {
                  addr: null,
                  prevMessages: _messages,
                  prevStream: stream,
                };
              } else {
                console.log(returnCell);
                this.active[cell.circuitId].prevMessages.push(
                  returnCell.encode()
                );
              }
            }
          } else {
            if (!this.active[nextHop.circuitId]) {
              console.log("here");
              const { messages: nextHopMessages, stream: nextHopStream } =
                await this.sendTorCell({
                  peerId: nextHop.multiaddr,
                  protocol: PROTOCOLS.message,
                  data: protocol.Cell.encode({
                    circuitId: nextHop.circuitId,
                    data: await aes.decrypt(cell.data as Uint8Array),
                    command: CellCommand.RELAY,
                  }).finish(),
                });
              this.active[nextHop.circuitId] = {
                addr: nextHop.multiaddr,
                messages: nextHopMessages,
                stream: nextHopStream,
                prevStream: stream,
              };
            } else {
              console.log("pushing tor cell to active hop");
              const { messages } = this.active[nextHop.circuitId];
              messages.push(
                protocol.Cell.encode({
                  circuitId: nextHop.circuitId,
                  data: await aes.decrypt(cell.data as Uint8Array),
                  command: CellCommand.RELAY,
                }).finish()
              );
            }
          }
        }
      }
    });
  };

  handleNextHopInfo(aes: crypto.aes.AESCipher, circuitId: number) {
    return async (data: Uint8Array, stream: Stream) => {
      const cell = Cell.decode(data);
      const circId = cell.circuitId;
      console.log("return cell received");
      const returnCell = protocol.Cell.encode({
        command: CellCommand.RELAY,
        circuitId: circuitId,
        data: await aes.encrypt(cell.data as Uint8Array),
      }).finish();
      console.log(this.active[circId]);
      if (this.active[circId].prevMessages) {
        this.active[circId].prevMessages.push(returnCell);
      } else {
        const { messages } = await this.sendTorCell({
          stream: this.active[circId].prevStream,
          data: returnCell,
        });
        this.active[circId].prevMessages = messages;
      }
    };
  }

  handleBaseMessageReceive(
    aes: crypto.aes.AESCipher,
    circuitId: number,
    hmac: any,
    prevStream: Stream
  ) {
    return async (data: Uint8Array, stream: Stream) => {
      const returnData = new Cell({
        command: CellCommand.RELAY,
        circuitId,
        data: await aes.encrypt(
          new RelayCell({
            data: data,
            streamId: circuitId,
            digest: await hmac.digest(data),
            len: data.length,
            command: RelayCellCommand.DATA,
          }).encode()
        ),
      }).encode();
      if (this.active[circuitId].prevMessages) {
        this.active[circuitId].prevMessages.push(returnData);
      } else {
        const { messages } = await this.sendTorCell({
          data: returnData,
          stream: prevStream,
        });
        //@ts-ignore
        if (!this.active[circuitId]) this.active[circuitId] = {};
        this.active[circuitId].prevMessages = messages;
      }
    };
  }

  async handleRelayCell({
    circuitId,
    relayCell,
    stream,
    nextCircuitId,
  }: {
    circuitId: number;
    relayCell: RelayCell;
    stream?: Stream;
    nextCircuitId?: number;
  }) {
    const { hmac } = this.keys[`${circuitId}`];
    const relayCellData = relayCell.data.subarray(0, relayCell.len);
    const hash = await hmac.digest(relayCellData);
    if (!equals(Uint8Array.from(hash.subarray(0, 6)), relayCell.digest))
      throw new Error("digest does not match");
    if (relayCell.command == RelayCellCommand.EXTEND) {
      return await this.handleRelayExtend({ circuitId, relayCellData, stream });
    }
    if (relayCell.command == RelayCellCommand.BEGIN) {
      return await this.handleRelayBegin({
        circuitId,
        relayCellData,
        stream,
        nextCircuitId,
      });
    }
    if (relayCell.command == RelayCellCommand.DATA) {
      return await this.handleRelayData({ circuitId, relayCellData, stream });
    }
  }
  async handleRelayData({
    circuitId,
    relayCellData,
  }: {
    circuitId: number;
    relayCellData: Uint8Array;
    stream?: Stream;
  }) {
    const { aes, hmac } = this.keys[`${circuitId}`];
    const activeInfo = this.active[circuitId];
    if (activeInfo) {
      if (!activeInfo.messages) {
        const { stream, messages } = await this.sendTorCell({
          peerId: activeInfo.addr,
          protocol: PROTOCOLS.baseMessage,
          data: relayCellData,
        });

        this.active[circuitId].messages = messages;
        this.active[circuitId].stream = stream;
      } else {
        activeInfo.messages.push(relayCellData);
      }
      return undefined;
    } else {
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
    nextCircuitId,
    stream: prevStream,
  }: {
    circuitId: number;
    relayCellData: Uint8Array;
    stream?: Stream;
    nextCircuitId?: number;
  }) {
    //change this so that the stream is kept active throughout the relay
    const { aes, hmac } = this.keys[`${circuitId}`];
    console.log("handling begin");
    const addr = multiaddr(relayCellData.slice(0, relayCellData.length));
    const { stream, messages } = await this.sendTorCell({
      peerId: addr,
      protocol: PROTOCOLS.baseMessage,
      data: protocol.BaseMessage.encode({
        type: "string",
        content: fromString("BEGIN"),
      }).finish(),
    });
    this.handleResponsesOnChannel({
      stream,
      handler: this.handleBaseMessageReceive(aes, circuitId, hmac, prevStream),
    });
    this.active[circuitId] = { addr, stream, messages };
  }
  async handleRelayExtend({
    circuitId,
    relayCellData,
    stream: prevStream,
  }: {
    circuitId: number;
    relayCellData: Uint8Array;
    stream?: Stream;
  }) {
    const { aes, hmac } = this.keys[`${circuitId}`];
    const encryptedKey = relayCellData.slice(0, 128);
    const multiAddr = multiaddr(relayCellData.slice(128));
    const hop = (this.keys[`${circuitId}`].nextHop = {
      multiaddr: multiAddr,
      circuitId: Buffer.from(crypto.randomBytes(16)).readUint16BE(),
    });
    const { stream, messages } = await this.sendTorCell({
      peerId: multiAddr,
      protocol: PROTOCOLS.message,
      data: new Cell({
        command: CellCommand.CREATE,
        data: encryptedKey,
        circuitId: hop.circuitId,
      }).encode(),
    });
    const details = {
      addr: multiAddr,
      messages,
      stream,
      prevStream,
      prevMessages: undefined,
    };
    if (this.active[circuitId].prevMessages) {
      details.prevMessages = this.active[circuitId].prevMessages;
    }
    this.active[circuitId] = details;
    const returnData = Cell.decode(await this.waitForSingularResponse(stream));
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
    this.handleResponsesOnChannel({
      stream: stream,
      handler: this.handleNextHopInfo(aes, circuitId),
    });
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
