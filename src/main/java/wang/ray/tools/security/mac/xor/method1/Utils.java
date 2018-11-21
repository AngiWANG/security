package wang.ray.tools.security.mac.xor.method1;

public class Utils {
	 public static String bcd2Str(byte[] b) {
	        char[] HEX_DIGITS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	        StringBuilder sb = new StringBuilder(b.length * 2);

	        for (int i = 0; i < b.length; ++i) {
	            sb.append(HEX_DIGITS[(b[i] & 240) >>> 4]);
	            sb.append(HEX_DIGITS[b[i] & 15]);
	        }

	        return sb.toString();
	    }

	    public static byte[] str2Bcd(String asc) {
	        int len = asc.length();
	        int mod = len % 2;
	        if (mod != 0) {
	            asc = "0" + asc;
	            len = asc.length();
	        }

	        byte[] abt = new byte[len];
	        if (len >= 2) {
	            len /= 2;
	        }

	        byte[] bbt = new byte[len];
	        abt = asc.getBytes();

	        for (int p = 0; p < asc.length() / 2; ++p) {
	            int j;
	            if (abt[2 * p] >= 97 && abt[2 * p] <= 122) {
	                j = abt[2 * p] - 97 + 10;
	            } else if (abt[2 * p] >= 65 && abt[2 * p] <= 90) {
	                j = abt[2 * p] - 65 + 10;
	            } else {
	                j = abt[2 * p] - 48;
	            }

	            int k;
	            if (abt[2 * p + 1] >= 97 && abt[2 * p + 1] <= 122) {
	                k = abt[2 * p + 1] - 97 + 10;
	            } else if (abt[2 * p + 1] >= 65 && abt[2 * p + 1] <= 90) {
	                k = abt[2 * p + 1] - 65 + 10;
	            } else {
	                k = abt[2 * p + 1] - 48;
	            }

	            int a = (j << 4) + k;
	            byte b = (byte) a;
	            bbt[p] = b;
	        }
	        return bbt;
	    }
}
