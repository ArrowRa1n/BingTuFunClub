# 冰兔w FunClub

#### 前言
“冰兔w FunClub”项目为个人作品，基于B站UP主“冰兔w”所创作的个人粉丝向网站。本项目分为前台展示网站和后台管理系统两个子项目组成，两个子项目都是采用的前后端分离的架构模式，前端使用的Vue开发框架，后端使用SpringBoot开发框架。其中，前台展示网站用来把数据转换成可视化的页面进行展览，后台管理系统用来对数据库的数据进行各种操作。

#### 前端技术架构
前端框架：Vue3 \
构建/打包工具：vite \
网络框架：Axios \
组件通信：Vuex \
组件库：element-ui \
路由：Vue-router \
第三方加密库：js-sha256、jsencrypt 

#### 后端技术架构
Web框架：Spring Boot 2.6.3 \
数据库ORM：Mybatis \
主数据库：MySQL 8 \
缓存数据库：Redis 5 \
权限拦截：Interceptor拦截器 \
异常参数过滤：Filter过滤器 \
加密库：java.security包 \
定时任务：Scheduled注解

#### 运行环境
Linux服务器 \
CentOS7.6操作系统 \
Docker容器化部署

#### 网站链接
http://1.12.253.195

#### 项目部分截图
![https://github.com/ArrowRa1n/MyImages/blob/main/bingtufunimgs/%E5%89%8D%E5%8F%B0%E5%B1%95%E7%A4%BA%E7%BD%91%E7%AB%99.png](https://github.com/ArrowRa1n/MyImages/raw/main/bingtufunimgs/%E5%89%8D%E5%8F%B0%E5%B1%95%E7%A4%BA%E7%BD%91%E7%AB%99.png)
![https://github.com/ArrowRa1n/MyImages/blob/main/bingtufunimgs/%E5%90%8E%E5%8F%B0%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%E7%99%BB%E9%99%86%E9%A1%B5.png](https://github.com/ArrowRa1n/MyImages/raw/main/bingtufunimgs/%E5%90%8E%E5%8F%B0%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%E7%99%BB%E9%99%86%E9%A1%B5.png)
![https://github.com/ArrowRa1n/MyImages/blob/main/bingtufunimgs/%E5%90%8E%E5%8F%B0%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F.png](https://github.com/ArrowRa1n/MyImages/raw/main/bingtufunimgs/%E5%90%8E%E5%8F%B0%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F.png)  


#### 项目部分代码
RSA工具类
```java
public class RSAUtil {
    //获取RSA密钥对，0公1私
    public  static Map<Integer, String> genKeyPair() throws NoSuchAlgorithmException {
        Map<Integer, String> keyMap=new HashMap<>();
        KeyPairGenerator keyPool = KeyPairGenerator.getInstance("RSA");
        keyPool.initialize(2048,new SecureRandom());
        KeyPair keyPair = keyPool.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        keyMap.put(0,publicKeyString);
        keyMap.put(1,privateKeyString);
        return  keyMap;
    }

    //公钥加密
    public  static String encrypt(String password,String publicKey) throws Exception {
        byte[] decode = Base64.getDecoder().decode(publicKey);
        PublicKey publicKeyEncrypt = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decode));
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE,publicKeyEncrypt);
        return Base64.getEncoder().encodeToString(rsa.doFinal(password.getBytes(StandardCharsets.UTF_8)));
    }

    //私钥解密
    public  static String decrypt(String encodedPassword,String privateKey) throws Exception {
        byte[] password = Base64.getDecoder().decode(encodedPassword);
        byte[] decode = Base64.getDecoder().decode(privateKey);
        PrivateKey privateKeyDecrypt = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decode));
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE,privateKeyDecrypt);
        return  new String(rsa.doFinal(password));
    }
}
```
SHA-256工具类
```java
public final class SHA256Util {
    private SHA256Util() {
        throw new AssertionError();
    }

    static MessageDigest sha256 = null;

    private static final int LEN = 12;

    public static final String SHA256_ALGORITHM = "SHA-256";
    static {
        try {
            sha256 = MessageDigest.getInstance(SHA256_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static byte[] getSalt(){
        byte[] salt=new byte[LEN];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public static byte[] encryptReturnByte(String password,byte[] salt) {
        Objects.requireNonNull(password, "password must not be null.");
        sha256.update(salt);
        sha256.update(password.getBytes());
        byte[] digest = sha256.digest();
        byte[] encryptBytes = new byte[LEN + digest.length];
        System.arraycopy(salt, 0, encryptBytes, 0, LEN);
        System.arraycopy(digest, 0, encryptBytes, LEN, digest.length);
        return encryptBytes;
    }

    public static byte[] encryptReturnByteAuto(String password) {
        Objects.requireNonNull(password, "password must not be null.");
        byte[] salt = getSalt();
        sha256.update(salt);
        sha256.update(password.getBytes());
        byte[] digest = sha256.digest();
        byte[] encryptBytes = new byte[LEN + digest.length];
        System.arraycopy(salt, 0, encryptBytes, 0, LEN);
        System.arraycopy(digest, 0, encryptBytes, LEN, digest.length);
        return encryptBytes;
    }

    public static String encryptReturnString(String password,byte[] salt) {
        byte[] bytes = encryptReturnByte(password,salt);
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static String encryptReturnString(String password) {
        byte[] bytes = encryptReturnByteAuto(password);
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static boolean validate(String password,byte[] salt, String encryptPassword) {
        if (password == null || password.isEmpty() || encryptPassword == null ||
                encryptPassword.isEmpty()||salt==null) {
            return false;
        }
        byte[] bytes = Base64.getDecoder().decode(encryptPassword);
        sha256.update(salt);
        sha256.update(password.getBytes());
        byte[] digest = sha256.digest();
        return Arrays.equals(digest, bytes);
    }
}
```
