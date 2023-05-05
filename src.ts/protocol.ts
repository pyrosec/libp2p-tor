import protobuf from "protobufjs";

import api from "./tor-protocol.json" assert { type: "json" };

const protocol: any = protobuf.Root.fromJSON(api).nested;

export { protocol };
