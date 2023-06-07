import { arrayify } from "@ethersproject/bytes";
import { Buffer } from "node:buffer";
import { protocol } from "./protocol";
export var CellCommand;
(function (CellCommand) {
    CellCommand[CellCommand["PADDING"] = 0] = "PADDING";
    CellCommand[CellCommand["CREATE"] = 1] = "CREATE";
    CellCommand[CellCommand["DESTROY"] = 2] = "DESTROY";
    CellCommand[CellCommand["RELAY"] = 3] = "RELAY";
    CellCommand[CellCommand["CREATED"] = 4] = "CREATED";
})(CellCommand || (CellCommand = {}));
export var RelayCellCommand;
(function (RelayCellCommand) {
    RelayCellCommand[RelayCellCommand["DATA"] = 0] = "DATA";
    RelayCellCommand[RelayCellCommand["BEGIN"] = 1] = "BEGIN";
    RelayCellCommand[RelayCellCommand["END"] = 2] = "END";
    RelayCellCommand[RelayCellCommand["TEARDOWN"] = 3] = "TEARDOWN";
    RelayCellCommand[RelayCellCommand["CONNECTED"] = 4] = "CONNECTED";
    RelayCellCommand[RelayCellCommand["EXTEND"] = 5] = "EXTEND";
    RelayCellCommand[RelayCellCommand["TRUNCATE"] = 6] = "TRUNCATE";
    RelayCellCommand[RelayCellCommand["SENDME"] = 7] = "SENDME";
    RelayCellCommand[RelayCellCommand["DROP"] = 8] = "DROP";
    RelayCellCommand[RelayCellCommand["EXTENDED"] = 9] = "EXTENDED";
})(RelayCellCommand || (RelayCellCommand = {}));
export class RelayCell {
    constructor(o) {
        this.streamId = o.streamId;
        this.digest = o.digest;
        this.len = o.len;
        this.command = o.command;
        this.data = o.data;
    }
    encode() {
        const result = Buffer.alloc(509);
        result.writeUInt16BE(this.streamId, 0);
        Buffer.from(this.digest).copy(result, 2, 0, 6);
        result.writeUInt16BE(this.len, 8);
        result.writeUInt8(this.command, 10);
        Buffer.from(this.data).copy(result, 11, 0, 498);
        return arrayify(result);
    }
    static from(relayCell) {
        const buf = Buffer.from(relayCell);
        return new RelayCell({
            streamId: buf.readUint16BE(),
            digest: buf.subarray(2, 8),
            len: buf.readUint16BE(8),
            command: buf.readUint8(10),
            data: buf.subarray(11, 509),
        });
    }
}
export class Cell {
    constructor(o) {
        this.circuitId = o.circuitId;
        this.command = o.command;
        this.data = o.data;
    }
    encode_raw() {
        const result = Buffer.alloc(512);
        result.writeUInt16BE(this.circuitId, 0);
        result.writeUInt8(this.command, 2);
        const data = Buffer.from((this.data instanceof RelayCell ? this.data.encode() : this.data));
        data.copy(result, 3, 0, 509);
        return arrayify(result);
    }
    encode() {
        return protocol.Cell.encode({
            circuitId: this.circuitId,
            data: this.data,
            command: this.command,
        }).finish();
    }
    static decode(data) {
        return new Cell(protocol.Cell.toObject(protocol.Cell.decode(data), {
            enums: Number,
            bytes: Uint8Array,
        }));
    }
    static from(cell) {
        const buf = Buffer.from(cell);
        const command = buf.readUint8(2);
        const circuitId = buf.readUint16BE();
        const data = new Uint8Array(buf.subarray(3, 512));
        return new Cell({
            circuitId,
            command,
            data,
        });
    }
}
export const PROTOCOLS = {
    message: "/tor/1.0.0/message",
    baseMessage: "/tor/1.0.0/baseMessage",
    advertise: "/tor/1.0.0/advertise",
    register: "/tor/1.0.0/register",
    relays: "/tor/1.0.0/relays",
};
//# sourceMappingURL=tor.js.map