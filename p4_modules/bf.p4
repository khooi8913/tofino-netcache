#define BF_ROW_SIZE 65536

control BF (
    inout my_ingress_headers_t hdr,
    out bit<1> is_reported
    ) 
{   
    bit<32>    index = 0;
    bit<1>     b0 = 0;
    bit<1>     b1 = 0;

    Hash<bit<32>>(HashAlgorithm_t.CRC32) h0;

    Register<bit<1>,bit<16>>(BF_ROW_SIZE) bf0;
    Register<bit<1>,bit<16>>(BF_ROW_SIZE) bf1;

    RegisterAction<bit<1>, _, bit<1>> (bf0) bf0_action = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 1;
        }
    };

    RegisterAction<bit<1>, _, bit<1>> (bf1) bf1_action = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 1;
        }
    };

    action update_bf0() {
        b0 = bf0_action.execute(index[31:16]);
    }

    action update_bf1() {
        b1 = bf1_action.execute(index[15:0]);
    }

    apply {
        index = h0.get({
            hdr.nc.key
        });

        update_bf0();
        update_bf1();

        is_reported = b0 & b1;
    }
}