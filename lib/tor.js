"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const bytes_1 = require("@ethersproject/bytes");
const buffer_1 = require("buffer");
var CellCommand;
(function (CellCommand) {
    CellCommand[CellCommand["PADDING"] = 0] = "PADDING";
    CellCommand[CellCommand["CREATE"] = 1] = "CREATE";
    CellCommand[CellCommand["DESTROY"] = 2] = "DESTROY";
    CellCommand[CellCommand["RELAY"] = 3] = "RELAY";
})(CellCommand || (CellCommand = {}));
var RelayCellCommand;
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
})(RelayCellCommand || (RelayCellCommand = {}));
class RelayCell {
    constructor(o) {
        this.streamId = o.streamId;
        this.digest = o.digest;
        this.len = o.len;
        this.command = o.command;
        this.data = o.data;
    }
    encode() {
        const result = buffer_1.Buffer.alloc(509);
        result.writeUInt16BE(0, this.streamId);
        buffer_1.Buffer.from(this.digest).copy(result, 2, 0, 6);
        result.writeUInt16BE(8, this.len);
        result.writeUInt8(10, this.command);
        buffer_1.Buffer.from(this.data).copy(result, 11, 0, 498);
        return (0, bytes_1.arrayify)(result);
    }
}
class Cell {
    constructor(o) {
        this.circuitId = o.circuitId;
        this.command = o.command;
        this.data = o.data;
    }
    encode() {
        const result = buffer_1.Buffer.alloc(512);
        result.writeUInt16BE(0, this.circuitId);
        result.writeUInt8(2, this.command);
        return (0, bytes_1.arrayify)(buffer_1.Buffer.from((this.data instanceof RelayCell ? this.data.encode() : this.data)).copy(result, 3, 0, 509));
    }
}
//# sourceMappingURL=tor.js.map