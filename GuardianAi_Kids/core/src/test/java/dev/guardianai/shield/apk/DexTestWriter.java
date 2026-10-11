package dev.guardianai.shield.apk;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Builds a minimal DEX image (header + string_ids + string_data) for tests. */
final class DexTestWriter {

    static byte[] dex(String... strings) {
        int header = 0x70;
        int idsOff = header;
        int dataOff = idsOff + strings.length * 4;
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        int[] offs = new int[strings.length];
        for (int k = 0; k < strings.length; k++) {
            offs[k] = dataOff + data.size();
            byte[] b = strings[k].getBytes(StandardCharsets.UTF_8);
            int len = strings[k].length();
            do {
                int c = len & 0x7F;
                len >>>= 7;
                data.write(len != 0 ? c | 0x80 : c);
            } while (len != 0);
            data.write(b, 0, b.length);
            data.write(0);
        }
        int total = dataOff + data.size();
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        bb.put("dex\n035\0".getBytes(StandardCharsets.ISO_8859_1));
        bb.putInt(0x20, total);
        bb.putInt(0x24, header);
        bb.putInt(0x28, 0x12345678);
        bb.putInt(0x38, strings.length);
        bb.putInt(0x3C, idsOff);
        for (int k = 0; k < strings.length; k++) bb.putInt(idsOff + k * 4, offs[k]);
        bb.position(dataOff);
        bb.put(data.toByteArray());
        return bb.array();
    }
}
