import cv2
import numpy as np
from scipy.fftpack import dct, idct


class DCTWatermark:
    def __init__(self, strength=0.1):
        self.strength = strength  # 水印强度系数
        self.block_size = 8  # DCT分块大小
        self.positions = [(3, 4), (4, 3)]  # 中频嵌入位置

    def _process_image(self, img):
        """预处理图像：确保尺寸为8的倍数"""
        h, w = img.shape[:2]
        return img[:h - h % self.block_size, :w - w % self.block_size]

    def embed(self, host, watermark):
        """嵌入水印"""
        host = self._process_image(cv2.cvtColor(host, cv2.COLOR_BGR2YCrCb))
        wm = watermark.astype(np.float32)

        # 在Y通道嵌入
        y_channel = host[:, :, 0].copy()
        for i in range(0, y_channel.shape[0], self.block_size):
            for j in range(0, y_channel.shape[1], self.block_size):
                block = y_channel[i:i + self.block_size, j:j + self.block_size]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

                # 嵌入中频系数
                for idx, (x, y) in enumerate(self.positions):
                    wm_val = wm[i // self.block_size % wm.shape[0],
                                j // self.block_size % wm.shape[1]]
                    dct_block[x, y] += self.strength * wm_val * 500

                block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
                y_channel[i:i + self.block_size, j:j + self.block_size] = block

        host[:, :, 0] = np.clip(y_channel, 0, 255)
        return cv2.cvtColor(host.astype(np.uint8), cv2.COLOR_YCrCb2BGR)

    def extract(self, watermarked_img, wm_shape):
        """提取水印"""
        marked = self._process_image(cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YCrCb))
        extracted = np.zeros(wm_shape)
        y_channel = marked[:, :, 0]

        for i in range(0, y_channel.shape[0], self.block_size):
            for j in range(0, y_channel.shape[1], self.block_size):
                block = y_channel[i:i + self.block_size, j:j + self.block_size]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

                # 计算差值
                diff = dct_block[self.positions[0]] - dct_block[self.positions[1]]
                idx_i = i // self.block_size % wm_shape[0]
                idx_j = j // self.block_size % wm_shape[1]
                extracted[idx_i, idx_j] = diff / self.strength

        return np.clip(extracted, 0, 1).astype(np.uint8)


# ====================== 鲁棒性测试工具 ======================
def robustness_test(attacked_img, extractor, original_wm):
    """测试鲁棒性并生成报告"""
    extracted = extractor.extract(attacked_img, original_wm.shape)
    similarity = (original_wm == extracted).mean()
    return extracted, similarity


def attack_flip(img, mode='horizontal'):
    """翻转攻击"""
    flip_code = 1 if mode == 'horizontal' else 0
    return cv2.flip(img, flip_code)


def attack_crop(img, ratio=0.2):
    """裁剪攻击"""
    h, w = img.shape[:2]
    cropped = img[int(h * ratio):int(h * (1 - ratio)), int(w * ratio):int(w * (1 - ratio))]
    return cv2.resize(cropped, (w, h))


def attack_translate(img, dx=30, dy=30):
    """平移攻击"""
    M = np.float32([[1, 0, dx], [0, 1, dy]])
    return cv2.warpAffine(img, M, (img.shape[1], img.shape[0]))


def attack_contrast(img, alpha=1.5):
    """对比度调整"""
    return cv2.convertScaleAbs(img, alpha=alpha, beta=0)


def attack_compress(img, quality=30):
    """JPEG压缩攻击"""
    _, buffer = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return cv2.imdecode(buffer, cv2.IMREAD_COLOR)


# ====================== 测试用例 ======================
if __name__ == "__main__":
    # 1. 读取内容
    host_img = cv2.imread('original.jpg')
    wm_img = cv2.imread('watermark.png', cv2.IMREAD_GRAYSCALE)
    wm_img = (wm_img > 128).astype(np.uint8)  # 二值化

    # 2. 嵌入水印
    embedder = DCTWatermark(strength=0.08)
    watermarked = embedder.embed(host_img, wm_img)
    cv2.imwrite('watermarked.png', watermarked)

    # 3. 测试鲁棒性
    attacks = [
        ('Original', watermarked),
        ('Horizontal Flip', attack_flip(watermarked)),
        ('Crop 20%', attack_crop(watermarked)),
        ('Translate (30px)', attack_translate(watermarked)),
        ('Contrast+50%', attack_contrast(watermarked, 1.5)),
        ('JPEG 30%', attack_compress(watermarked, 30))
    ]

    print(f"{'Attack Type':<20} | {'Similarity':<10}")
    print("-" * 35)
    for name, attacked_img in attacks:
        _, similarity = robustness_test(attacked_img, embedder, wm_img)
        print(f"{name:<20} | {similarity:.4f}")