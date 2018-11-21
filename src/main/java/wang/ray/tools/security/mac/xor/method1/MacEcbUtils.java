package wang.ray.tools.security.mac.xor.method1;


import wang.ray.tools.security.mac.ByteUtil;

public class MacEcbUtils {

	public static void main(String[] args) throws Exception{
//        byte[] key = new byte[]{0x5C, (byte) 0xBE, 0x7E, 0x38, (byte) 0xA1, 0x46, (byte) 0xFD, 0x5C};
//        byte[] input = new byte[]{0x01, 0x02, 0x03};
//        System.out.println(Utils.bcd2Str(getMac(key, input)));
        
    	String bmk1 = "E84D768E9952E066";
		String mak1 = "9999999999999999";
		String mak11 = "A5A650450C050A1B";
		
		String bmk2 = "9999999999999999";
		String mak2 = "E84D768E9952E066";
		String mak22 = "BCDE50BA3B337586";
		
		// mac A8FE110404D07A72
		String data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + 
				"<MESSAGE><MHEAD><VERSION>2.0</VERSION><PROCCODE>P1001</PROCCODE><MERNO>822855059430001</MERNO><TERID>47767796</TERID><TRANMERNO>822855059430001</TRANMERNO><BANKCODE>48220000</BANKCODE><PTIME>20181120103152</PTIME></MHEAD><MBODY><POLICYID>36015868647886</POLICYID><VERIFICACODE>58686865</VERIFICACODE></MBODY></MESSAGE>";
//		String data = "3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554462D38223F3E0A3C4D4553534147453E3C4D484541443E3C56455253494F4E3E322E303C2F56455253494F4E3E3C50524F43434F44453E50313030313C2F50524F43434F44453E3C4D45524E4F3E3832323835353035393433303030313C2F4D45524E4F3E3C54455249443E34373736373739363C2F54455249443E3C5452414E4D45524E4F3E3832323835353035393433303030313C2F5452414E4D45524E4F3E3C42414E4B434F44453E34383232303030303C2F42414E4B434F44453E3C5054494D453E32303138313132303130333135323C2F5054494D453E3C2F4D484541443E3C4D424F44593E3C504F4C49435949443E33363031353836383634373838363C2F504F4C49435949443E3C5645524946494341434F44453E35383638363836353C2F5645524946494341434F44453E3C2F4D424F44593E3C2F4D4553534147453E";
		
//		4144373542353433
		
		System.out.println(ByteUtil.getHexStr(getMac(ByteUtil.getHexByte(mak1),data.getBytes("utf-8"))));
    }

    /**
     * mac计算
     *
     * @param key   mac秘钥
     * @param Input 待加密数据
     * @return
     */
    public static byte[] getMac(byte[] key, byte[] Input) {
        int length = Input.length;
        int x = length % 8;
        // 需要补位的长度
        int addLen = 0;
        if (x != 0) {
            addLen = 8 - length % 8;
        }
        int pos = 0;
        // 原始数据补位后的数据
        byte[] data = new byte[length + addLen];
        System.arraycopy(Input, 0, data, 0, length);
        byte[] oper1 = new byte[8];
        System.arraycopy(data, pos, oper1, 0, 8);
        pos += 8;
        // 8字节异或
        for (int i = 1; i < data.length / 8; i++) {
            byte[] oper2 = new byte[8];
            System.arraycopy(data, pos, oper2, 0, 8);
            byte[] t = bytesXOR(oper1, oper2);
            oper1 = t;
            pos += 8;
        }
        // 将异或运算后的最后8个字节（RESULT BLOCK）转换成16个HEXDECIMAL：
        String result = bytesToHexString(oper1);
        byte[] resultBlock = result.getBytes();
        // 取前8个字节MAK加密
        byte[] front8 = new byte[8];
        System.arraycopy(resultBlock, 0, front8, 0, 8);
        byte[] behind8 = new byte[8];
        System.arraycopy(resultBlock, 8, behind8, 0, 8);
        byte[] desfront8 = DesUtils.encrypt(front8, key);
        // 将加密后的结果与后8 个字节异或：
        byte[] resultXOR = bytesXOR(desfront8, behind8);
        // 用异或的结果TEMP BLOCK 再进行一次单倍长密钥算法运算
        byte[] buff = DesUtils.encrypt(resultXOR, key);
        // 将运算后的结果（ENC BLOCK2）转换成16 个HEXDECIMAL asc
        byte[] retBuf = new byte[8];
        // 取8个长度字节就是mac值
        String result1 = bytesToHexString(buff);
        System.arraycopy(result1.getBytes(), 0, retBuf, 0, 8);
        return retBuf;
    }

    /**
     * 单字节异或
     *
     * @param src1
     * @param src2
     * @return
     */
    public static byte byteXOR(byte src1, byte src2) {
        return (byte) ((src1 & 0xFF) ^ (src2 & 0xFF));
    }

    /**
     * 字节数组异或
     *
     * @param src1
     * @param src2
     * @return
     */
    public static byte[] bytesXOR(byte[] src1, byte[] src2) {
        int length = src1.length;
        if (length != src2.length) {
            return null;
        }
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = byteXOR(src1[i], src2[i]);
        }
        return result;
    }

    /**
     * 字节数组转HEXDECIMAL
     *
     * @param bArray
     * @return
     */
    public static final String bytesToHexString(byte[] bArray) {
        StringBuffer sb = new StringBuffer(bArray.length);
        String sTemp;
        for (int i = 0; i < bArray.length; i++) {
            sTemp = Integer.toHexString(0xFF & bArray[i]);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

}
