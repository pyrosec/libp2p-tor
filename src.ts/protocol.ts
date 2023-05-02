import * as protobuf from "protobufjs";

const api = require("./tor-protocol.json");

const protocol: any = protobuf.Root.fromJSON(api).nested.libp2p_tor;

export { protocol };
