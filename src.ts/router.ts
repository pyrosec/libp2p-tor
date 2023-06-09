import { RelayCell, Cell, CellCommand, RelayCellCommand } from "./tor";
import { generateEphemeralKeyPair } from "@libp2p/crypto/keys";
import { toString, fromString } from "uint8arrays";
import { Multiaddr } from "@multiformats/multiaddr";
import type { Libp2pOptions } from "libp2p";
import type { BaseMessageHandler } from "./libp2p.wrapper";
import { Libp2pWrapped } from "./libp2p.wrapper";
import { pipe } from "it-pipe";
import { encode, decode } from "it-length-prefixed";
import { ECDHKey } from "@libp2p/crypto/keys/interface";
import * as crypto from "@libp2p/crypto";
import { Buffer } from "node:buffer";
import { iv } from "./constants";
import { equals } from "uint8arrays";
import { multiaddr } from "multiaddr";
import type { PrivateKey } from "@libp2p/interface-keys";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import type { PeerInfo } from "@libp2p/interface-peer-info";
import { protocol } from "./protocol";
import type { Stream } from "@libp2p/interface-connection";
import { PROTOCOLS } from "./tor";
import type { Pushable } from "it-pushable";

type HmacType = Awaited<ReturnType<typeof crypto.hmac.create>>;
const rsa = crypto.keys.supportedKeys.rsa;
type Key = {
  ecdhKeys: ECDHKey[];
  hops: Multiaddr[];
  keys: Uint8Array[];
  aes: crypto.aes.AESCipher[];
  hmac: HmacType[];
  activeStream?: Stream;
  circuitIds: Record<string, number>;
};

type RendezvousKey = {
  pubKey: Uint8Array;
  ecdhKey: ECDHKey;
  aes: crypto.aes.AESCipher;
  hmac: HmacType;
  key: PrivateKey;
  cookie: Uint8Array;
  circuitId: number;
  hash: Uint8Array;
};

const createHmac = crypto.hmac.create;
export class Router extends Libp2pWrapped {
  public registries: Multiaddr[];
  public advertiseKey: PrivateKey;
  public advertiseIds: Record<string, number>;
  public proxies: {
    publicKey: {
      encrypt: (bytes: Uint8Array) => Promise<Buffer>;
      marshal: () => Uint8Array;
    };
    id: string;
    addr: Multiaddr;
  }[];
  public rendezvousKeys: Record<number, RendezvousKey>;
  public keys: Record<number, Key>;
  public activeStreams: Record<
    number,
    { stream: Stream; messages: Pushable<any> }
  >;
  public testId?: number;

  constructor(registries: Multiaddr[]) {
    super();
    this.registries = registries;
    this.keys = {};
    this.advertiseIds = {};
    this.rendezvousKeys = {};
    this.activeStreams = {};
    this.type = "ROUTER";
  }

  async build(length: number = 1) {
    const circId = await this.create();
    console.log("created 1 ");
    await Array.from(new Array(length - 1)).reduce(async (a) => {
      await a;
      return this.extend(circId);
    }, Promise.resolve());
    return circId;
  }

  async extend(circId: number) {
    const endProxy = this.proxies.filter(
      (d) => !this.keys[circId].hops.includes(d.addr)
    )[0];
    console.log("extending");
    const { key, genSharedKey } = await generateEphemeralKeyPair("P-256");
    this.keys[circId].ecdhKeys.push({ key, genSharedKey });
    this.keys[circId].hops.push(endProxy.addr);
    const hop = endProxy.addr.bytes;
    const encryptedKey = Uint8Array.from(
      await endProxy.publicKey.encrypt(Uint8Array.from(key))
    );
    const relayCellData = new Uint8Array(encryptedKey.length + hop.length);
    relayCellData.set(encryptedKey);
    relayCellData.set(hop, encryptedKey.length);
    const hmac = await crypto.hmac.create(
      "SHA256",
      this.keys[circId].keys[this.keys[circId].keys.length - 1]
    );
    const digest = await hmac.digest(relayCellData);
    const _relay = new RelayCell({
      streamId: Buffer.from(crypto.randomBytes(2)).readUint16BE(),
      command: RelayCellCommand.EXTEND,
      data: relayCellData,
      digest,
      len: relayCellData.length,
    }).encode();
    const encryptedRelay = await [...this.keys[circId].aes]
      .reverse()
      .reduce(async (a, aes, i) => {
        return await aes.encrypt(await a);
      }, Promise.resolve(_relay));
    this.activeStreams[circId].messages.push(
      protocol.Cell.encode({
        command: CellCommand.RELAY,
        circuitId: circId,
        data: encryptedRelay,
      }).finish()
    );
    const returnData = await this.waitForResponseOnChannel("extended");
    const cellKey = returnData.subarray(0, 65);
    const cellDigest = returnData.subarray(65, 65 + 32);
    const cellSharedKey = await genSharedKey(cellKey);
    const cellHmac = await crypto.hmac.create("SHA256", cellSharedKey);
    this.keys[`${circId}`].hmac.push(cellHmac);
    if (
      !equals(cellDigest, Uint8Array.from(await cellHmac.digest(cellSharedKey)))
    )
      throw new Error("digest does not match");
    this.keys[`${circId}`].keys.push(cellSharedKey);
    this.keys[`${circId}`].aes.push(await crypto.aes.create(cellSharedKey, iv));
    console.log(
      "relay extended to length:",
      this.keys[`${circId}`].keys.length
    );
  }

  async send(data: any, circuitId: number) {
    if (!circuitId) circuitId = Number(Object.keys(this.keys))[0];
    const keys = this.keys[`${circuitId}`];
    const { messages } = this.activeStreams[circuitId];
    const hmacLast = keys.hmac[keys.hmac.length - 1];
    const relayCell = new RelayCell({
      command: RelayCellCommand.DATA,
      data,
      streamId: Buffer.from(crypto.randomBytes(2)).readUint16BE(),
      digest: await hmacLast.digest(data),
      len: data.length,
    }).encode();
    const encodedData = await [...keys.aes].reverse().reduce(async (a, aes) => {
      return await aes.encrypt(await a);
    }, Promise.resolve(relayCell));
    const cell = new Cell({
      command: CellCommand.RELAY,
      circuitId,
      data: encodedData,
    }).encode();
    await this.pushTorCell({
      data: cell,
      messages,
    });
  }

  createHandlerForResponsesOnCircuit = (circuitId: number) => {
    return async (data: Uint8Array, stream: Stream) => {
      const decodedCell = Cell.decode(data);
      if (decodedCell.command === CellCommand.CREATED) {
        this.sendMessageToResponseChannel("created", data);
        return true;
      }
      const keys = this.keys[`${circuitId}`];
      const hmacLast = keys.hmac[keys.hmac.length - 1];
      const relayCell = RelayCell.from(
        await keys.aes.reduce(async (a, aes) => {
          return aes.decrypt(await a);
        }, Promise.resolve(decodedCell.data as Uint8Array))
      );
      if (
        !equals(
          relayCell.digest,
          (
            await hmacLast.digest(relayCell.data.slice(0, relayCell.len))
          ).subarray(0, 6)
        )
      )
        throw new Error("relay digest does not match");
      if (relayCell.command == RelayCellCommand.END) return false;
      if (relayCell.command == RelayCellCommand.EXTENDED) {
        this.sendMessageToResponseChannel("extended", relayCell.data);
        return true;
      }
      const baseMessage = protocol.BaseMessage.decode(
        relayCell.data.slice(0, relayCell.len)
      );
      if (this.baseMessageHandlers[baseMessage["type"]])
        this.baseMessageHandlers[baseMessage["type"]](
          baseMessage,
          decodedCell.circuitId
        );
      return true;
    };
  };

  async decodeReturnCell(returnCell: Cell, keys: Key) {
    const returnData = await keys.aes.reduce(async (a, _aes) => {
      return await _aes.decrypt(await a);
    }, Promise.resolve(returnCell.data as Uint8Array));
    const returnRelayCell = RelayCell.from(returnData);
    if (
      equals(
        (
          await keys.hmac[keys.hmac.length - 1].digest(
            returnRelayCell.data.subarray(0, returnRelayCell.len)
          )
        ).subarray(0, 6),
        returnRelayCell.digest
      )
    ) {
      return returnRelayCell;
    } else {
      throw new Error("digest doesnt match");
    }
  }

  async begin(peer: Multiaddr, circuitId: number = null) {
    //TODO: remove this later
    if (!circuitId) circuitId = Number(Object.keys(this.keys)[0]);
    const keys = this.keys[`${circuitId}`];
    const hmacLast = keys.hmac[keys.hmac.length - 1];
    const data = peer.bytes;
    const relayCell = new RelayCell({
      command: RelayCellCommand.BEGIN,
      data,
      streamId: Buffer.from(crypto.randomBytes(2)).readUint16BE(),
      digest: await hmacLast.digest(data),
      len: data.length,
    }).encode();
    const encodedData = await [...keys.aes].reverse().reduce(async (a, aes) => {
      return await aes.encrypt(await a);
    }, Promise.resolve(relayCell));
    const { messages } = this.activeStreams[circuitId];
    messages.push(
      protocol.Cell.encode({
        command: CellCommand.RELAY,
        circuitId,
        data: encodedData,
      }).finish()
    );
    const cid = Number(await this.waitForResponseOnChannel("begin"));
    if (!this.keys[`${circuitId}`].circuitIds)
      this.keys[`${circuitId}`].circuitIds = {};

    this.keys[`${circuitId}`].circuitIds[peer.toString()] = cid;
    return cid;
  }

  async create() {
    const circId = Buffer.from(crypto.randomBytes(2)).readUint16BE();
    const { genSharedKey, key } = await generateEphemeralKeyPair("P-256");
    const proxy = this.proxies[0];
    const encryptedKey = Uint8Array.from(await proxy.publicKey.encrypt(key));
    const { stream, messages } = await this.sendTorCell({
      peerId: proxy.addr,
      protocol: PROTOCOLS.message,
      data: protocol.Cell.encode({
        command: CellCommand.CREATE,
        data: encryptedKey,
        circuitId: circId,
      }).finish(),
    });
    const handler = this.createHandlerForResponsesOnCircuit(circId);
    this.handleResponsesOnChannel({
      stream,
      handler,
    });
    const cell = Cell.decode(await this.waitForResponseOnChannel("created"));
    const proxyEcdhKey = (cell.data as Uint8Array).slice(0, 65);
    const digest = (cell.data as Uint8Array).slice(65, 65 + 32);
    const sharedKey = await genSharedKey(proxyEcdhKey);
    const hmac = await crypto.hmac.create("SHA256", sharedKey);
    if (!equals(await hmac.digest(sharedKey), digest)) {
      throw new Error("wrong digest");
    }
    this.keys[circId] = {
      ecdhKeys: [
        {
          genSharedKey,
          key,
        },
      ],
      keys: [sharedKey],
      hops: [proxy.addr],
      aes: [await crypto.aes.create(sharedKey, iv)],
      hmac: [hmac],
      circuitIds: {},
    };
    this.activeStreams[circId] = {
      messages,
      stream,
    };
    return circId;
  }

  async advertise() {
    const points = await this.pickAdvertisePoints();
    await points.reduce(async (_a, p) => {
      await _a;
      const stream = await this.dialProtocol(p, PROTOCOLS.advertise);
      await pipe([this.advertiseKey.public.marshal()], encode(), stream.sink);
      const id = await this.build(3);
      const bid = await this.begin(p, id);
      console.log("begun", id);
      await this.send(
        protocol.BaseMessage.encode({
          type: PROTOCOLS.rendezvous.begin,
          content: this.advertiseKey.public.marshal(),
          circuitId: bid,
        }).finish(),
        id
      );
      this.advertiseIds[p.toString()] = id;
    }, Promise.resolve());
    this.on("rendezvous:response", async (data) => {
      //TODO: write this out
      console.log("response data received");

      //@ts-ignore
      const payload1 = await this.advertiseKey.decrypt(
        data.content.subarray(0, 128)
      );
      //@ts-ignore
      const payload2 = await this.advertiseKey.decrypt(
        data.content.subarray(128, 256)
      );
      const cookie = payload1.subarray(0, 32);
      const key = payload1.subarray(32);
      const ecdhKey = await generateEphemeralKeyPair("P-256");
      const sharedKey = await ecdhKey.genSharedKey(key);
      const hmac = await createHmac("SHA256", sharedKey);
      console.log(this.rendezvousKeys);
      this.rendezvousKeys[data.baseCircuitId] = {
        cookie: cookie,
        ecdhKey,
        hmac,
        aes: await crypto.aes.create(sharedKey, iv),
        pubKey: payload2,
        key: null,
        circuitId: data.circuitId,
        hash: await hmac.digest(sharedKey),
      };
      console.log("emitting");
      this.emit("rendezvous/test1:response", "");
    });
  }

  async pickRendezvous(circuitId: number) {
    const key = this.rendezvousKeys[circuitId];
    const data = new Uint8Array(
      key.cookie.length + key.ecdhKey.key.length + key.hash.length
    );
    data.set(key.cookie);
    data.set(key.ecdhKey.key, key.cookie.length);
    data.set(key.hash, key.ecdhKey.key.length);
    const bid = await this.begin(multiaddr(key.pubKey), circuitId);
    this.send(
      protocol.BaseMessage.encode({
        circuitId: bid,
        type: PROTOCOLS.rendezvous.cookieResponse,
        content: data,
      }).finish(),
      circuitId
    );
  }

  async pickAdvertisePoints(): Promise<Multiaddr[]> {
    return this.proxies.map((d) => d.addr).slice(0, 2);
  }

  async pickRendezvousPoint(): Promise<Multiaddr> {
    return this.proxies[this.proxies.length - 1].addr;
  }

  handleBaseMessageRendezvousCookieRecieve: BaseMessageHandler = async (
    baseMessage,
    circuitId
  ) => {
    this.emit(`rendezvous:response`, {
      ...baseMessage,
      baseCircuitId: circuitId,
    });
    return false;
    //TODO: write out how to create introduction point
  };
  handleBaseMessageRendezvousCookieResponse: BaseMessageHandler = async (
    baseMessage,
    circuitId
  ) => {
    this.emit(`rendezvous:response`, {
      ...baseMessage,
      baseCircuitId: circuitId,
    });
    return false;
    //TODO: write out how to create introduction point
  };
  async rendezvous(pubKey: Uint8Array) {
    const hash = await sha256.digest(pubKey);
    const cid = CID.create(1, 0x01, hash);
    const cookie = crypto.randomBytes(32);
    const _pubKey = rsa.unmarshalRsaPublicKey(pubKey);
    const rendezvousKey = await crypto.keys.generateKeyPair("RSA", 1024);
    const peers = this._libp2p.contentRouting
      .findProviders(cid)
      [Symbol.asyncIterator]();
    const peer: PeerInfo = (await peers.next()).value;
    const circuitId = await this.build(3);
    //@ts-ignore
    this.rendezvousKeys[circuitId] = {};
    const { key, genSharedKey } = await generateEphemeralKeyPair("P-256");
    this.rendezvousKeys[circuitId].ecdhKey = { key, genSharedKey };
    this.rendezvousKeys[circuitId].key = rendezvousKey;
    this.rendezvousKeys[circuitId].pubKey = pubKey;
    this.rendezvousKeys[circuitId].cookie = cookie;
    const rendezvousPoint = await this.pickRendezvousPoint();
    const circuitId2 = await this.build(3);
    const cookieAwaitBid = await this.begin(rendezvousPoint, circuitId2);
    await this.send(
      protocol.BaseMessage.encode({
        type: PROTOCOLS.rendezvous.cookieAwait,
        content: cookie,
        circuitId: cookieAwaitBid,
      }).finish(),
      circuitId2
    );
    const payload = new Uint8Array(cookie.length + key.length);
    //TODO: handle this elegantly
    if (payload.length > 509) throw new Error("overflowing relaycell length");
    payload.set(cookie);
    //65
    payload.set(key, cookie.length);
    //162

    const encryptedPayload1 = Uint8Array.from(_pubKey.encrypt(payload));
    const encryptedPayload2 = Uint8Array.from(
      _pubKey.encrypt(rendezvousPoint.bytes)
    );
    const finalPayload = new Uint8Array(256 + pubKey.length);
    finalPayload.set(encryptedPayload1);
    finalPayload.set(encryptedPayload2, encryptedPayload1.length);
    finalPayload.set(pubKey, 256);
    const _cid = await this.begin(peer.multiaddrs[1], circuitId);
    console.log("sending rendezvous cookie");
    await this.send(
      protocol.BaseMessage.encode({
        type: PROTOCOLS.rendezvous.cookie,
        content: finalPayload,
        circuitId: _cid,
      }).finish(),
      circuitId
    );
    //TODO: make this pass keys through rendezvous point
  }
  async fetchKeys() {
    this.proxies = await this.registries.reduce<
      Promise<{ id: string; addr: Multiaddr; publicKey: any }[]>
    >(async (results, registry) => {
      try {
        console.log("dialing registry");
        const stream = await this.dialProtocol(registry, PROTOCOLS.relays);
        const _results = await pipe(
          stream.source,
          decode(),
          async function (source) {
            let str = "";
            for await (const data of source) {
              str += toString(data.subarray());
            }
            const _peers = JSON.parse(str);
            return _peers.map(
              ({
                id,
                addr,
                publicKey,
              }: {
                id: string;
                publicKey: any;
                addr: string;
              }) => {
                return {
                  id,
                  addr: multiaddr(addr),
                  publicKey: rsa.unmarshalRsaPublicKey(
                    Uint8Array.from(Object.values(publicKey))
                  ),
                };
              }
            );
          }
        );

        return [...(await results), ..._results];
      } catch (e) {
        console.log(e.errors);
      }
    }, Promise.resolve([]));
  }

  async run(options: Libp2pOptions) {
    await super.run(options);
    await this.fetchKeys();

    this.advertiseKey = await crypto.keys.generateKeyPair("RSA", 1024);
    this.baseMessageHandlers[PROTOCOLS.rendezvous.cookieRecieve] =
      this.handleBaseMessageRendezvousCookieRecieve;
    this.baseMessageHandlers[PROTOCOLS.rendezvous.cookieResponse] =
      this.handleBaseMessageRendezvousCookieResponse;
    //await this.advertise();
  }
}
