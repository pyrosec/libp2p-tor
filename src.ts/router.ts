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

type HmacType = Awaited<ReturnType<typeof crypto.hmac.create>>;
const rsa = crypto.keys.supportedKeys.rsa;
type Key = {
  ecdhKeys: ECDHKey[];
  hops: Multiaddr[];
  keys: Uint8Array[];
  aes: crypto.aes.AESCipher[];
  hmac: HmacType[];
  activeStream?: Stream;
};

type RendezvousKey = {
  pubKey: Uint8Array;
  ecdhKey: ECDHKey;
  aes: crypto.aes.AESCipher;
  hmac: HmacType;
  key: PrivateKey;
  cookie: Uint8Array;
};

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
  public activeStreams: Record<number, Stream>;

  constructor(registries: Multiaddr[]) {
    super();
    this.registries = registries;
    this.keys = {};
    this.advertiseIds = {};
    this.rendezvousKeys = {};
    this.activeStreams = {};
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
    const proxy = this.keys[circId].hops[0];
    const ret = await this.sendTorCellWithResponse({
      peerId: proxy,
      protocol: PROTOCOLS.message,
      data: protocol.Cell.encode({
        command: CellCommand.RELAY,
        circuitId: circId,
        data: encryptedRelay,
      }).finish(),
    });
    const returnCell = Cell.decode(ret);
    const returnRelayCell = RelayCell.from(
      await this.keys[`${circId}`].aes.reduce(async (a, aes) => {
        return await aes.decrypt(await a);
      }, Promise.resolve(returnCell.data as Uint8Array))
    );
    if (returnRelayCell.command == RelayCellCommand.END)
      throw new Error("error extending");
    const cellKey = returnRelayCell.data.subarray(0, 65);
    const cellDigest = returnRelayCell.data.subarray(65, 65 + 32);
    const cellSharedKey = await genSharedKey(cellKey);
    const cellHmac = await crypto.hmac.create("SHA256", cellSharedKey);
    const prevHmac =
      this.keys[`${circId}`].hmac[this.keys[`${circId}`].hmac.length - 1];
    const digestInput = new Uint8Array(returnRelayCell.len);
    digestInput.set(returnRelayCell.data.slice(0, returnRelayCell.len));
    if (
      !equals(
        returnRelayCell.digest,
        (await prevHmac.digest(digestInput)).subarray(0, 6)
      )
    )
      throw new Error("relay digest does not match");
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

  async send(data: any, circuitId: number = null) {
    if (!circuitId) circuitId = Number(Object.keys(this.keys))[0];
    const keys = this.keys[`${circuitId}`];
    const stream = this.keys[`${circuitId}`].activeStream;
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
    await this.sendTorCell({
      data: cell,
      stream,
    });
  }

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
    const stream = await this.sendTorCell({
      peerId: keys.hops[0],
      data: protocol.Cell.encode({
        command: CellCommand.RELAY,
        circuitId,
        data: encodedData,
      }).finish(),
      protocol: PROTOCOLS.message,
    });
    const res = await this.waitForSingularResponse(stream);
    const resultCell = await this.decodeReturnCell(
      protocol.Cell.decode(res),
      keys
    );
    if (resultCell.command == RelayCellCommand.END)
      throw new Error("Couldn't begin the circuit");
    this.keys[`${circuitId}`].activeStream = stream;
  }

  async create() {
    const circId = Buffer.from(crypto.randomBytes(2)).readUint16BE();
    const { genSharedKey, key } = await generateEphemeralKeyPair("P-256");
    const proxy = this.proxies[0];
    const encryptedKey = Uint8Array.from(await proxy.publicKey.encrypt(key));
    const ret = await this.sendTorCellWithResponse({
      peerId: proxy.addr,
      protocol: PROTOCOLS.message,
      data: protocol.Cell.encode({
        command: CellCommand.CREATE,
        data: encryptedKey,
        circuitId: circId,
      }).finish(),
    });
    const cell = Cell.decode(ret);
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
      await this.begin(p, id);
      await this.send(
        protocol.BaseMessage.encode({
          type: "rendezvous/begin",
          content: toString(this.advertiseKey.public.marshal()),
        }).finish(),
        id
      );
      this.advertiseIds[p.toString()] = id;
    }, Promise.resolve());
  }

  async pickAdvertisePoints(): Promise<Multiaddr[]> {
    return this.proxies.map((d) => d.addr).slice(0, 2);
  }

  async pickRendezvousPoint(): Promise<Uint8Array> {
    return this.proxies[this.proxies.length - 1].addr.bytes;
  }

  handleBaseMessageRendezvousCookieRecieve: BaseMessageHandler = async ({
    stream,
    baseMessage,
  }) => {
    //TODO: write out how to create introduction point
  };
  async rendezvous(pubKey: Uint8Array) {
    const hash = await sha256.digest(pubKey);
    const cid = CID.create(1, 0x01, hash);
    const cookie = crypto.randomBytes(32);
    const _pubKey = rsa.unmarshalRsaPublicKey(pubKey);
    const rendezvousKey = await crypto.keys.generateKeyPair("RSA", 4096);
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
    const payload = new Uint8Array(cookie.length + key.length);
    //TODO: handle this elegantly
    if (payload.length > 509) throw new Error("overflowing relaycell length");
    payload.set(cookie);
    //65
    payload.set(key, cookie.length);
    //162

    const encryptedPayload1 = Uint8Array.from(_pubKey.encrypt(payload));
    const encryptedPayload2 = Uint8Array.from(_pubKey.encrypt(rendezvousPoint));
    const finalPayload = new Uint8Array(256 + pubKey.length);
    finalPayload.set(encryptedPayload1);
    finalPayload.set(encryptedPayload2, encryptedPayload1.length);
    finalPayload.set(pubKey, encryptedPayload2.length);
    await this.begin(peer.multiaddrs[1], circuitId);
    await this.send(
      protocol.BaseMessage.encode({
        type: "rendezvous/cookie",
        content: finalPayload,
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

    this.advertiseKey = await crypto.keys.generateKeyPair("RSA", 4096);
    this.baseMessageHandlers["rendezvous/cookie/recieve"] =
      this.handleBaseMessageRendezvousCookieRecieve;
    //await this.advertise();
  }
}
