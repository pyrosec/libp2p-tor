export declare enum CellCommand {
    PADDING = 0,
    CREATE = 1,
    DESTROY = 2,
    RELAY = 3,
    CREATED = 4
}
export declare enum RelayCellCommand {
    DATA = 0,
    BEGIN = 1,
    END = 2,
    TEARDOWN = 3,
    CONNECTED = 4,
    EXTEND = 5,
    TRUNCATE = 6,
    SENDME = 7,
    DROP = 8,
    EXTENDED = 9
}
interface RelayCellLike {
    streamId: number;
    digest: Uint8Array;
    len: number;
    command: RelayCellCommand;
    data: Uint8Array;
}
export declare class RelayCell implements RelayCellLike {
    streamId: number;
    digest: Uint8Array;
    len: number;
    command: RelayCellCommand;
    data: Uint8Array;
    constructor(o: {
        streamId: number;
        command: RelayCellCommand;
        digest: Uint8Array;
        len: number;
        data: Uint8Array;
    });
    encode(): Uint8Array;
    static from(relayCell: Uint8Array): RelayCell;
}
export declare class Cell {
    circuitId: number;
    command: CellCommand;
    data: Uint8Array | RelayCellLike;
    constructor(o: {
        circuitId: number;
        command: CellCommand;
        data: Uint8Array | RelayCellLike;
    });
    encode_raw(): Uint8Array;
    encode(): any;
    static decode(data: any): Cell;
    static from(cell: Uint8Array): Cell;
}
export declare const PROTOCOLS: {
    message: string;
    baseMessage: string;
    advertise: string;
    register: string;
    relays: string;
};
export {};
