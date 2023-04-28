import { arrayify } from "@ethersproject/bytes";
import { Buffer } from "node:buffer";

export enum CellCommand {
  PADDING,
  CREATE,
  DESTROY,
  RELAY,
  CREATED,
}

export enum RelayCellCommand {
  DATA,
  BEGIN,
  END,
  TEARDOWN,
  CONNECTED,
  EXTEND,
  TRUNCATE,
  SENDME,
  DROP,
  EXTENDED,
}

interface RelayCellLike {
  streamId: number;
  digest: Uint8Array;
  len: number;
  command: RelayCellCommand;
  data: Uint8Array;
}

export class RelayCell implements RelayCellLike {
  public streamId: number;
  public digest: Uint8Array;
  public len: number;
  public command: RelayCellCommand;
  public data: Uint8Array;
  constructor(o: {
    streamId: number;
    command: RelayCellCommand;
    digest: Uint8Array;
    len: number;
    data: Uint8Array;
  }) {
    this.streamId = o.streamId;
    this.digest = o.digest;
    this.len = o.len;
    this.command = o.command;
    this.data = o.data;
  }
  encode() {
    const result = Buffer.alloc(509);
    result.writeUInt16BE(this.streamId, 0);
    Buffer.from(this.digest as any).copy(result, 2, 0, 6);
    result.writeUInt16BE(this.len, 8);
    result.writeUInt8(this.command, 10);
    Buffer.from(this.data as any).copy(result, 11, 0, 498);
    return arrayify(result);
  }
  static from(relayCell: Uint8Array): RelayCell {
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
  public circuitId: number;
  public command: CellCommand;
  public data: Uint8Array | RelayCellLike;
  constructor(o: {
    circuitId: number;
    command: CellCommand;
    data: Uint8Array | RelayCellLike;
  }) {
    this.circuitId = o.circuitId;
    this.command = o.command;
    this.data = o.data;
  }
  encode(): Uint8Array {
    const result = Buffer.alloc(512);
    result.writeUInt16BE(this.circuitId, 0);
    result.writeUInt8(this.command, 2);
    const data = Buffer.from(
      (this.data instanceof RelayCell ? this.data.encode() : this.data) as any
    );
    data.copy(result, 3, 0, 509);
    return arrayify(result);
  }

  static from(cell: Uint8Array): Cell {
    const buf = Buffer.from(cell);
    const command: CellCommand = buf.readUint8(2);
    const circuitId = buf.readUint16BE();
    const data = new Uint8Array(buf.subarray(3, 512));

    return new Cell({
      circuitId,
      command,
      data,
    });
  }
}
