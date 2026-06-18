public class VNPayConfig {

    // ❌ RỦI RO BẢO MẬT: Khóa bí mật bị hardcode trực tiếp trong mã nguồn

    public static final String HASH_SECRET = "VNPAY_SECRET_KEY_123456_ABCD_XYZ";

    public static final String VNP_URL = "https://sandbox.vnpayment.vn/paymentv2/vpcpay.html";

} Bạn là một lập trình viên Java Backend có kinh nghiệm tích hợp cổng thanh toán VNPay.

Hãy viết một lớp Java tên là VNPayPaymentService để hỗ trợ tạo giao dịch thanh toán VNPay.

Các yêu cầu bắt buộc:



Tuyệt đối không hardcode API Key, Secret Key, Access Token hoặc bất kỳ thông tin nhạy cảm nào trong mã nguồn.

Sử dụng biến môi trường (Environment Variable) để nạp khóa bí mật bằng hàm System.getenv().

Tên biến môi trường chứa khóa bí mật là VNPAY_HASH_SECRET.

Khi khởi tạo service, phải kiểm tra giá trị của biến môi trường:

Nếu biến môi trường không tồn tại (null)

Hoặc là chuỗi rỗng sau khi trim()

Thì phải ném ra ngoại lệ IllegalStateException với thông báo rõ ràng.

Viết phương thức tạo chữ ký SHA512 cho dữ liệu thanh toán sử dụng khóa bí mật lấy từ biến môi trường.

Mã nguồn phải tuân thủ các nguyên tắc bảo mật cơ bản:

Không ghi log giá trị Secret Key.

Không trả Secret Key ra API response.

Không lưu Secret Key dưới dạng hằng số trong code.

Trả về mã nguồn Java hoàn chỉnh kèm chú thích giải thích các phần quan trọng. 

Chào bạn, một lập trình viên Java Backend luôn đặt bảo mật lên hàng đầu là một điểm cộng rất lớn! Việc loại bỏ hardcode và chuyển sang sử dụng biến môi trường là bước đi hoàn toàn chính xác để bảo vệ vnp_HashSecret của dự án.

Dưới đây là mã nguồn Java hoàn chỉnh cho lớp VNPayPaymentService đáp ứng đầy đủ các yêu cầu nghiêm ngặt của bạn, sử dụng thuật toán HmacSHA512 (chuẩn bảo mật hiện tại của VNPay) để tạo chữ ký dữ liệu.

💻 Mã nguồn Java: VNPayPaymentService
Java
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Service xử lý tạo giao dịch và ký số cho cổng thanh toán VNPay.
 * Đảm bảo các nguyên tắc bảo mật, không hardcode thông tin nhạy cảm.
 */
public class VNPayPaymentService {

    // Khóa bí mật được lưu trong bộ nhớ instance sau khi đã validate thành công
    private final String hashSecret;
    private static final String HMAC_SHA512 = "HmacSHA512";

    /**
     * Constructor của Service.
     * Kiểm tra nghiêm ngặt biến môi trường ngay khi khởi tạo hệ thống.
     * * @throws IllegalStateException nếu cấu hình VNPAY_HASH_SECRET thiếu hoặc rỗng.
     */
    public VNPayPaymentService() {
        // 1. Đọc giá trị từ biến môi trường
        String secret = System.getenv("VNPAY_HASH_SECRET");

        // 2. Kiểm tra điều kiện: Không null và không được là chuỗi rỗng sau khi trim()
        if (secret == null || secret.trim().isEmpty()) {
            // Log cảnh báo hệ thống (Tuyệt đối không in giá trị secret ra log ở đây)
            System.err.println("[CRITICAL] Cấu hình bảo mật lỗi: Thiếu biến môi trường VNPAY_HASH_SECRET!");
            
            throw new IllegalStateException(
                "Không thể khởi tạo VNPayPaymentService: Biến môi trường 'VNPAY_HASH_SECRET' chưa được cấu hình hoặc hợp lệ."
            );
        }

        // 3. Gán giá trị hợp lệ vào biến local để sử dụng nội bộ
        this.hashSecret = secret.trim();
    }

    /**
     * Phương thức tạo chữ ký SHA512 (vnp_SecureHash) cho dữ liệu thanh toán VNPay.
     * Sử dụng TreeMap để tự động sắp xếp các tham số theo thứ tự alphabet (quy định của VNPay).
     * * @param fields Tập hợp các tham số gửi sang VNPay (vnp_TxnRef, vnp_Amount,...)
     * @return Chuỗi chữ ký số Hexadecimal dạng viết hoa
     */
    public String generateSecureHash(Map<String, String> fields) {
        if (fields == null || fields.isEmpty()) {
            throw new IllegalArgumentException("Dữ liệu băm (fields) không được để trống.");
        }

        // Tự động sắp xếp các tham số theo thứ tự alphabet của key bằng TreeMap
        Map<String, String> sortedFields = new TreeMap<>(fields);

        // Tạo chuỗi query data (key1=value1&key2=value2)
        String signData = sortedFields.entrySet().stream()
                .filter(entry -> entry.getValue() != null && !entry.getValue().isEmpty())
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));

        // Thực hiện ký HmacSHA512 với chuỗi dữ liệu và hashSecret
        return hmacSHA512(this.hashSecret, signData);
    }

    /**
     * Hàm băm dữ liệu sử dụng thuật toán HmacSHA512
     */
    private String hmacSHA512(final String key, final String data) {
        try {
            if (key == null || data == null) {
                throw new NullPointerException("Key hoặc Data để băm không được null");
            }
            
            final Mac hmacSHA512 = Mac.getInstance(HMAC_SHA512);
            byte[] hmacKeyBytes = key.getBytes(StandardCharsets.UTF_8);
            final SecretKeySpec secretKey = new SecretKeySpec(hmacKeyBytes, HMAC_SHA512);
            hmacSHA512.init(secretKey);
            
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] result = hmacSHA512.doFinal(dataBytes);
            
            // Chuyển đổi mảng byte sang chuỗi Hex (Hexadecimal)
            StringBuilder sb = new StringBuilder(2 * result.length);
            for (byte b : result) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString().toUpperCase(); // VNPay yêu cầu chữ ký dạng viết hoa
            
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Lỗi hệ thống khi khởi tạo thuật toán băm HmacSHA512", e);
        }
    }
}
🔍 Điểm nhấn thiết kế & Tuân thủ Bảo mật
Bảo vệ tuyệt đối Secret Key: Khóa không được lưu vào bất kỳ hằng số (static final) nào. Biến hashSecret được đánh dấu private final, chỉ hiển thị bên trong phạm vi của đối tượng VNPayPaymentService.

Fail-fast (Thất bại sớm): Ngay khi ứng dụng khởi chạy và tạo instance của service này, hàm Constructor sẽ quét biến môi trường. Nếu DevOps quên cấu hình VNPAY_HASH_SECRET, hệ thống sẽ ném ngay IllegalStateException dừng ứng dụng lại thay vì chạy tiếp và gây lỗi giao dịch lỗi mờ ám về sau.

An toàn thông tin (No-Log): Đoạn mã kiểm tra lỗi (System.err.println) chỉ đưa ra thông báo thiếu biến, tuyệt đối không in/log giá trị bí mật ra bảng điều khiển hoặc tệp tin log.

Sắp xếp chuẩn VNPay: Sử dụng TreeMap giúp tự động hóa việc gom và sắp xếp các tham số thanh toán theo bảng chữ cái từ A-Z trước khi tiến hành băm dữ liệu, đảm bảo thuật toán sinh mã hash luôn chính xác với phía VNPay.

💡 Mẹo nhỏ khi triển khai: Ở môi trường local (máy cá nhân), bạn nhớ cấu hình biến môi trường VNPAY_HASH_SECRET trong file .env, docker-compose.yml, hoặc trong phần Run/Debug Configurations của IDE (IntelliJ IDEA/Eclipse) để test code mượt mà nhé!