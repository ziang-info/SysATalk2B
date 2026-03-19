public import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import com.google.common.util.concurrent.RateLimiter;

@RestController
@RequestMapping("/v1/auth")
public class MobileLoginController {

    // 系统A的AppID和AppSecret（建议配置在Nacos/配置文件，避免硬编码）
    @Value("${systemA.appId:SYSTEM_A_001}")
    private String systemAId;
    @Value("${systemA.appSecret:abc1234567890def}")
    private String systemASecret;

    // 限流：100次/分钟
    private final RateLimiter rateLimiter = RateLimiter.create(100.0 / 60);

    // 模拟用户数据库
    private final Map<String, User> userDb = new HashMap<>();

    /**
     * 手机号登录/注册接口
     */
    @PostMapping("/mobile-login")
    public Map<String, Object> mobileLogin(@RequestBody Map<String, Object> requestParam, HttpServletRequest request) {
        Map<String, Object> result = new HashMap<>();

        // 1. 限流校验
        if (!rateLimiter.tryAcquire(1, TimeUnit.SECONDS)) {
            result.put("code", 429);
            result.put("msg", "请求过于频繁，请稍后重试");
            result.put("data", null);
            return result;
        }

        try {
            // 2. 基础参数校验
            String appId = (String) requestParam.get("appId");
            String mobile = (String) requestParam.get("mobile");
            Long timestamp = (Long) requestParam.get("timestamp");
            String sign = (String) requestParam.get("sign");
            String nonce = (String) requestParam.get("nonce");

            if (appId == null || mobile == null || timestamp == null || sign == null || nonce == null) {
                result.put("code", 400);
                result.put("msg", "参数缺失");
                result.put("data", null);
                return result;
            }

            // 校验手机号格式（11位数字）
            if (!mobile.matches("^1[3-9]\\d{9}$")) {
                result.put("code", 400);
                result.put("msg", "手机号格式错误");
                result.put("data", null);
                return result;
            }

            // 校验时间戳（5分钟内有效）
            long currentTime = System.currentTimeMillis();
            if (Math.abs(currentTime - timestamp) > 5 * 60 * 1000) {
                result.put("code", 400);
                result.put("msg", "请求已过期");
                result.put("data", null);
                return result;
            }

            // 3. 签名校验
            String generateSign = DigestUtils.md5Hex(appId + timestamp + mobile + nonce + systemASecret).toLowerCase();
            if (!systemAId.equals(appId) || !generateSign.equals(sign)) {
                result.put("code", 401);
                result.put("msg", "签名验证失败");
                result.put("data", null);
                return result;
            }

            // 4. 核心业务逻辑：查询/新建用户 + 登录
            boolean createNew = false;
            User user = userDb.get(mobile);
            if (user == null) {
                // 新建用户
                user = new User();
                user.setUserId("USER_" + System.currentTimeMillis()); // 生成唯一ID
                user.setMobile(mobile);
                userDb.put(mobile, user);
                createNew = true;
            }

            // 生成登录token（实际项目建议用JWT，设置过期时间）
            String token = DigestUtils.md5Hex(user.getUserId() + System.currentTimeMillis() + systemASecret);

            // 5. 组装响应数据
            Map<String, Object> data = new HashMap<>();
            data.put("token", token);
            data.put("userId", user.getUserId());
            data.put("mobile", mobile);
            data.put("createNew", createNew);

            result.put("code", 200);
            result.put("msg", "登录成功");
            result.put("data", data);

        } catch (Exception e) {
            // 异常捕获，避免接口崩溃
            result.put("code", 500);
            result.put("msg", "系统内部错误");
            result.put("data", null);
            // 实际项目需记录异常日志
            e.printStackTrace();
        }

        return result;
    }

    // 模拟用户实体
    static class User {
        private String userId;
        private String mobile;

        // getter/setter
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getMobile() { return mobile; }
        public void setMobile(String mobile) { this.mobile = mobile; }
    }
} {
    
}
