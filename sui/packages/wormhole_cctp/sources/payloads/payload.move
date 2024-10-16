module wormhole_cctp::payload {
    use wormhole::bytes;
    use wormhole::cursor;
    use wormhole_cctp::deposit::{Self, Deposit};

    #[error]
    const EInvalidPayload: vector<u8> =
            b"Invalid payload type.";

    public enum Payload {
        Deposit(Deposit),
    }

    public fun new_deposit(d: Deposit): Payload {
        Payload::Deposit(d)
    }

    public fun deposit(payload: Payload): Deposit {
        match (payload) {
            Payload::Deposit(d) => d,
        }
    }

    public fun serialize(payload: Payload): vector<u8> {
        let mut buf = vector::empty<u8>();
        match (payload) {
            Payload::Deposit(d) => {
                bytes::push_u8(&mut buf, 1);
                buf.append(d.serialize());
            }
        };
        buf
    }

    public fun parse(buf: vector<u8>): Payload {
        let mut cur = cursor::new(buf);
        let payload_type = bytes::take_u8(&mut cur);
        let payload = match (payload_type) {
            1 => Payload::Deposit(deposit::take_bytes(&mut cur)),
            _ => abort(EInvalidPayload)
        };
        cur.destroy_empty();
        payload
    }
}
