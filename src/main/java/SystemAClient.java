import org.apache.commons.codec.digest.DigestUtils;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SystemAClient {
    // 系统B接口地址
    private static final String API_URL = "https://api.系统B域名.com/v1/auth/mobile-login";
    // 系统A的AppID和AppSecret
    private static final String APP_ID = "SYSTEM_A_001";
    private static final String APP_SECRET = "abc1234567890def";

    public static void main(String[] args) {
        // 要传递的手机号
        String mobile = "13800138000";
        // 1. 生成请求参数
        Map<String, Object> params = new HashMap<>();
        params.put("appId", APP_ID);
        params.put("mobile", mobile);
        params.put("timestamp", System.currentTimeMillis());
        params.put("nonce", UUID.randomUUID().toString().replace("-", "").substring(0, 8)); // 8位随机串

        // 2. 生成签名
        String sign = DigestUtils.md5Hex(
                APP_ID + params.get("timestamp") + mobile + params.get("nonce") + APP_SECRET
        ).toLowerCase();
        params.put("sign", sign);

        // 3. 发送POST请求（实际项目用OkHttp/HttpClient）
        // 此处省略HTTP请求代码，核心是传递JSON参数并接收响应
        System.out.println("请求参数：" + params);
    }
}