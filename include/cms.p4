typedef bit<32> count_t;

#define SKETCH_CTR_PER_ROW 32768 

control CMS (
    inout my_ingress_headers_t hdr,
    out count_t flow_count
    ) 
{   
    bit<32>     index = 0;
    count_t     count_r0 = 0;
    count_t     count_r1 = 0;

    Hash<bit<32>>(HashAlgorithm_t.CRC32) h0;
    Register<count_t,_>(SKETCH_CTR_PER_ROW) sketch0;
    Register<count_t,_>(SKETCH_CTR_PER_ROW) sketch1;

    RegisterAction<count_t, _, count_t> (sketch0) sketch0_count = {
        void apply(inout count_t val, out count_t rv) {
            val = val |+| 1;
            rv = val;
        }
    };

    RegisterAction<count_t, _, count_t> (sketch1) sketch1_count = {
        void apply(inout count_t val, out count_t rv) {
            val = val |+| 1;
            rv = val;
        }
    };

    action update_sketch0() {
        count_r0 = sketch0_count.execute(index[31:16]);
    }

     action update_sketch1() {
        count_r1 = sketch1_count.execute(index[15:0]);
    }

    apply {
        index = h0.get({
            hdr.nc.key
        });

        update_sketch0();
        update_sketch1();

        flow_count = min(count_r0, count_r1);
    }
}