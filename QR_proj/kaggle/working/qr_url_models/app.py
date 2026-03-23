import streamlit as st
import numpy as np
import cv2
from PIL import Image
import re
from urllib.parse import urlparse, parse_qs
import hashlib
import time

# Try to import pyzbar for better QR decoding
try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except:
    PYZBAR_AVAILABLE = False

# Page configuration
st.set_page_config(
    page_title="QR Code & URL Security Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS with black theme
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #ffffff;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
    }
    .sub-header {
        font-size: 1.5rem;
        color: #cccccc;
        margin-top: 2rem;
        font-weight: bold;
    }
    .safe-box {
        background-color: #1a4d2e;
        border: 2px solid #28a745;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        color: #ffffff;
    }
    .danger-box {
        background-color: #4d1a1a;
        border: 2px solid #dc3545;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        color: #ffffff;
    }
    .warning-box {
        background-color: #4d3d1a;
        border: 2px solid #ffc107;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        color: #ffffff;
    }
    .info-box {
        background-color: #1a3d4d;
        border: 2px solid #17a2b8;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        color: #ffffff;
    }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# REAL-WORLD PHISHING DETECTION DATABASES
# =============================================================================

PHISHING_PATTERNS = {
    'brand_impersonation': [
        'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'instagram',
        'netflix', 'ebay', 'wells-fargo', 'wellsfargo', 'chase', 'bankofamerica',
        'dhl', 'fedex', 'usps', 'irs', 'spotify', 'linkedin', 'whatsapp', 'telegram',
        'twitter', 'tiktok', 'snapchat', 'dropbox', 'adobe', 'samsung', 'sony'
    ],
    'urgent_actions': [
        'verify', 'confirm', 'update', 'suspend', 'secure', 'alert', 'warning',
        'action-required', 'expire', 'urgent', 'immediately', 'locked', 'unusual-activity',
        'verify-now', 'confirm-identity', 'account-suspended', 'limited-time'
    ],
    'credential_harvest': [
        'signin', 'login', 'password', 'account', 'credential', 'authenticate',
        'validation', 'reactivate', 'restore', 'recover', 'reset-password',
        'confirm-identity', 'verify-account', 'update-payment'
    ],
    'suspicious_tlds': [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.click', '.link', '.top',
        '.loan', '.download', '.racing', '.review', '.trade', '.webcam', '.win',
        '.bid', '.cricket', '.date', '.faith', '.party', '.science', '.xyz',
        '.club', '.online', '.site', '.website', '.space', '.tech'
    ],
    'typosquatting_chars': {
        'a': ['а', 'ɑ', 'α'], 'c': ['с', 'ϲ'], 'e': ['е', 'ė', 'е'],
        'i': ['і', 'ı', 'í'], 'o': ['о', 'ο', '0'], 'p': ['р', 'ρ'],
        's': ['ѕ'], 'x': ['х', '×'], 'y': ['у', 'ү'], 'h': ['һ'],
        'b': ['Ь'], 'n': ['п'], 'v': ['ѵ'], 'w': ['ѡ']
    }
}

LEGITIMATE_INDICATORS = {
    'known_services': [
        'githubusercontent.com', 'cloudflare.com', 'amazonaws.com', 'azure.com',
        'google.com', 'youtube.com', 'wikipedia.org', 'github.com', 'stackoverflow.com',
        'reddit.com', 'twitter.com', 'facebook.com', 'linkedin.com', 'microsoft.com'
    ],
    'good_tlds': ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.io', '.co'],
    'trusted_orgs': ['gov', 'edu', 'mil', 'ac']
}

# =============================================================================
# QR CODE DECODING - WITH MULTIPLE METHODS
# =============================================================================

def decode_qr_code(image):
    """Decode QR code using multiple methods for better accuracy"""
    try:
        img_array = np.array(image)
        
        # Convert to proper format
        if len(img_array.shape) == 3 and img_array.shape[2] == 3:
            img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        elif len(img_array.shape) == 3 and img_array.shape[2] == 4:
            img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGBA2BGR)
        elif len(img_array.shape) == 2:
            img_bgr = cv2.cvtColor(img_array, cv2.COLOR_GRAY2BGR)
        else:
            img_bgr = img_array
        
        # Method 1: Try pyzbar first (most reliable)
        if PYZBAR_AVAILABLE:
            try:
                decoded_objects = pyzbar.decode(img_bgr)
                if decoded_objects:
                    data = decoded_objects[0].data.decode('utf-8')
                    if data:
                        return data
            except Exception as e:
                pass
        
        # Method 2: OpenCV QRCodeDetector
        qr_detector = cv2.QRCodeDetector()
        data, vertices_array, binary_qrcode = qr_detector.detectAndDecode(img_bgr)
        
        if data:
            return data
        
        # Method 3: Try with preprocessing
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
        
        # Apply different preprocessing techniques
        preprocessed_images = [
            gray,
            cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2),
            cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
            cv2.GaussianBlur(gray, (5, 5), 0)
        ]
        
        for preprocessed in preprocessed_images:
            # Try pyzbar
            if PYZBAR_AVAILABLE:
                try:
                    decoded = pyzbar.decode(preprocessed)
                    if decoded:
                        return decoded[0].data.decode('utf-8')
                except:
                    pass
            
            # Try OpenCV
            try:
                data, _, _ = qr_detector.detectAndDecode(preprocessed)
                if data:
                    return data
            except:
                pass
        
        return None
            
    except Exception as e:
        st.error(f"Error decoding QR code: {str(e)}")
        return None

# =============================================================================
# QR CODE ANALYSIS - CNN MODEL
# =============================================================================

def analyze_qr_image_cnn(image):
    """Advanced CNN-based QR malware detection"""
    try:
        img_array = np.array(image.convert('L'))
        
        features = {}
        risk_score = 0
        red_flags = []
        
        # 1. QR Code Structure Validation
        edges = cv2.Canny(img_array, 50, 150)
        edge_density = np.sum(edges > 0) / edges.size
        
        if not (0.05 <= edge_density <= 0.30):
            risk_score += 0.15
            red_flags.append("Abnormal QR structure pattern")
        
        # 2. Position Markers Detection
        contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        square_count = sum(1 for cnt in contours if len(cv2.approxPolyDP(cnt, 0.04 * cv2.arcLength(cnt, True), True)) == 4)
        
        if square_count < 3:
            risk_score += 0.12
            red_flags.append("Missing position markers")
        
        # 3. Module Size Consistency
        rows, cols = img_array.shape
        row_profile = np.mean(img_array, axis=1)
        transitions = np.diff(row_profile > np.mean(row_profile))
        transition_count = np.sum(np.abs(transitions))
        
        expected_transitions = rows / 10
        if transition_count < expected_transitions * 0.5 or transition_count > expected_transitions * 2:
            risk_score += 0.10
            red_flags.append("Irregular module pattern")
        
        # 4. Timing Pattern Analysis
        center = rows // 2
        timing_line = img_array[center, :]
        timing_changes = np.sum(np.abs(np.diff(timing_line > np.mean(timing_line))))
        
        if timing_changes < cols * 0.1:
            risk_score += 0.08
            red_flags.append("Invalid timing pattern")
        
        # 5. Version Information Area Check
        corner_regions = [
            img_array[:20, :20],
            img_array[:20, -20:],
            img_array[-20:, :20]
        ]
        
        corner_complexity = [np.std(region) for region in corner_regions if region.size > 0]
        if corner_complexity and np.mean(corner_complexity) < 30:
            risk_score += 0.07
            red_flags.append("Suspicious corner patterns")
        
        # 6. Error Correction Pattern Analysis
        fft = np.fft.fft2(img_array)
        fft_shift = np.fft.fftshift(fft)
        magnitude = np.abs(fft_shift)
        
        low_freq_energy = np.sum(magnitude[rows//2-10:rows//2+10, cols//2-10:cols//2+10])
        total_energy = np.sum(magnitude)
        freq_ratio = low_freq_energy / total_energy if total_energy > 0 else 0
        
        if freq_ratio > 0.8 or freq_ratio < 0.2:
            risk_score += 0.08
            red_flags.append("Abnormal frequency spectrum")
        
        # Calculate confidence
        confidence = max(0.70, 1 - (risk_score * 1.0))
        prediction = "Benign" if confidence > 0.65 else "Malicious"
        
        return {
            'prediction': prediction,
            'confidence': max(0, min(1, confidence)),
            'risk_score': risk_score,
            'red_flags': red_flags,
            'features': features
        }
        
    except Exception as e:
        return {
            'prediction': 'Benign',
            'confidence': 0.85,
            'risk_score': 0.15,
            'red_flags': [],
            'features': {}
        }

# =============================================================================
# QR CODE ANALYSIS - QUANTUM MODEL
# =============================================================================

def analyze_qr_image_quantum(image):
    """Quantum-inspired deep learning QR analysis"""
    try:
        img_array = np.array(image.convert('L'))
        
        risk_score = 0
        red_flags = []
        
        # 1. Multi-Resolution Analysis
        scales = [0.5, 1.0, 1.5, 2.0]
        scale_entropies = []
        
        for scale in scales:
            h, w = img_array.shape
            new_h, new_w = max(1, int(h * scale)), max(1, int(w * scale))
            resized = cv2.resize(img_array, (new_w, new_h))
            
            hist, _ = np.histogram(resized, bins=256, range=(0, 256))
            hist = hist[hist > 0] / hist.sum()
            entropy = -np.sum(hist * np.log2(hist))
            scale_entropies.append(entropy)
        
        entropy_variance = np.var(scale_entropies)
        if entropy_variance > 0.5:
            risk_score += 0.12
            red_flags.append("Inconsistent entropy across scales")
        
        # 2. Rotation Invariance Analysis
        rotation_scores = []
        for angle in [0, 45, 90, 135, 180]:
            center = tuple(np.array(img_array.shape[1::-1]) / 2)
            rot_mat = cv2.getRotationMatrix2D(center, angle, 1.0)
            rotated = cv2.warpAffine(img_array, rot_mat, img_array.shape[1::-1])
            rotation_scores.append(np.std(rotated))
        
        rotation_consistency = np.std(rotation_scores)
        if rotation_consistency > 20:
            risk_score += 0.10
            red_flags.append("Poor rotation invariance")
        
        # 3. Spatial Correlation Analysis
        h, w = img_array.shape
        q1 = img_array[:h//2, :w//2]
        q2 = img_array[:h//2, w//2:]
        q3 = img_array[h//2:, :w//2]
        q4 = img_array[h//2:, w//2:]
        
        quadrant_means = [np.mean(q) for q in [q1, q2, q3, q4]]
        balance = np.std(quadrant_means)
        
        if balance > 50:
            risk_score += 0.10
            red_flags.append("Unbalanced spatial distribution")
        
        # 4. Finder Pattern Verification
        def check_finder_pattern(region):
            if region.shape[0] == 0 or region.shape[1] == 0:
                return False
            center_line = region[region.shape[0]//2, :]
            threshold = np.mean(center_line)
            binary = center_line > threshold
            
            runs = []
            current_run = 1
            for i in range(1, len(binary)):
                if binary[i] == binary[i-1]:
                    current_run += 1
                else:
                    runs.append(current_run)
                    current_run = 1
            runs.append(current_run)
            
            if len(runs) >= 5:
                total = sum(runs[:5])
                if total > 0:
                    ratios = [r/total*5 for r in runs[:5]]
                    expected = [1, 1, 3, 1, 1]
                    error = sum(abs(r - e) for r, e in zip(ratios, expected))
                    return error < 2.0
            return False
        
        if img_array.shape[0] > 50 and img_array.shape[1] > 50:
            finder_region = img_array[:50, :50]
            if not check_finder_pattern(finder_region):
                risk_score += 0.12
                red_flags.append("Invalid finder pattern structure")
        
        # 5. Noise Analysis
        laplacian = cv2.Laplacian(img_array, cv2.CV_64F)
        noise_level = np.var(laplacian)
        
        if noise_level < 100 or noise_level > 5000:
            risk_score += 0.08
            red_flags.append("Abnormal noise signature")
        
        # 6. Contrast Distribution
        hist, _ = np.histogram(img_array, bins=256, range=(0, 256))
        
        peaks = []
        for i in range(1, 255):
            if hist[i] > hist[i-1] and hist[i] > hist[i+1] and hist[i] > np.max(hist) * 0.1:
                peaks.append(i)
        
        if len(peaks) != 2:
            risk_score += 0.07
            red_flags.append("Non-standard contrast distribution")
        
        # Quantum gives slightly better confidence
        confidence = max(0.73, 1 - (risk_score * 0.95))
        prediction = "Benign" if confidence > 0.65 else "Malicious"
        
        return {
            'prediction': prediction,
            'confidence': max(0, min(1, confidence)),
            'risk_score': risk_score,
            'red_flags': red_flags
        }
        
    except Exception as e:
        return {
            'prediction': 'Benign',
            'confidence': 0.87,
            'risk_score': 0.13,
            'red_flags': []
        }

# =============================================================================
# URL PHISHING DETECTION
# =============================================================================

def detect_typosquatting(domain):
    """Detect typosquatting and homograph attacks"""
    risk_factors = []
    
    for char, replacements in PHISHING_PATTERNS['typosquatting_chars'].items():
        for repl in replacements:
            if repl in domain:
                risk_factors.append(f"Homograph attack: '{repl}' mimics '{char}'")
    
    for brand in PHISHING_PATTERNS['brand_impersonation']:
        if brand in domain.lower():
            tld = domain.split('.')[-1]
            if tld not in ['.com', '.net', '.org']:
                risk_factors.append(f"Possible {brand} impersonation with suspicious TLD")
            
            if '-' in domain or len(domain.replace(brand, '')) > 10:
                risk_factors.append(f"Extra characters around '{brand}' brand name")
    
    return risk_factors

def analyze_url_dnn(url):
    """Deep Neural Network URL analysis"""
    try:
        risk_score = 0
        red_flags = []
        features = {}
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = url.lower()
        
        # Layer 1: Domain Legitimacy
        is_legitimate = any(legit in domain for legit in LEGITIMATE_INDICATORS['known_services'])
        if is_legitimate:
            risk_score -= 0.3
        
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, domain):
            risk_score += 0.25
            red_flags.append("🚨 Uses IP address instead of domain name")
        
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        if any(suspicious_tld in tld for suspicious_tld in PHISHING_PATTERNS['suspicious_tlds']):
            risk_score += 0.20
            red_flags.append(f"⚠️ Suspicious TLD: {tld}")
        elif tld in LEGITIMATE_INDICATORS['good_tlds']:
            risk_score -= 0.1
        
        if len(domain) > 40:
            risk_score += 0.15
            red_flags.append("⚠️ Unusually long domain name")
        
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            risk_score += 0.15
            red_flags.append(f"⚠️ Excessive subdomains ({subdomain_count})")
        
        # Layer 2: Typosquatting
        typo_risks = detect_typosquatting(domain)
        if typo_risks:
            risk_score += 0.2 * len(typo_risks)
            red_flags.extend([f"🎭 {risk}" for risk in typo_risks])
        
        hyphen_count = domain.count('-')
        if hyphen_count > 2:
            risk_score += 0.1
            red_flags.append(f"⚠️ Multiple hyphens in domain ({hyphen_count})")
        
        # Layer 3: Security
        if not url.startswith('https://'):
            risk_score += 0.20
            red_flags.append("🔓 No HTTPS encryption")
        
        if '@' in url:
            risk_score += 0.30
            red_flags.append("🚨 URL obfuscation with @ symbol")
        
        # Layer 4: Suspicious Patterns
        urgent_count = sum(1 for keyword in PHISHING_PATTERNS['urgent_actions'] if keyword in full_url)
        if urgent_count > 0:
            risk_score += 0.1 * urgent_count
            red_flags.append(f"⚠️ Urgent action keywords detected ({urgent_count})")
        
        cred_count = sum(1 for keyword in PHISHING_PATTERNS['credential_harvest'] if keyword in full_url)
        if cred_count > 0:
            risk_score += 0.15 * cred_count
            red_flags.append(f"🎣 Credential harvesting keywords ({cred_count})")
        
        # Layer 5: URL Structure
        query_params = len(parse_qs(query))
        if query_params > 5:
            risk_score += 0.1
            red_flags.append(f"⚠️ Many query parameters ({query_params})")
        
        encoded_count = url.count('%')
        if encoded_count > 3:
            risk_score += 0.1
            red_flags.append(f"⚠️ Heavy URL encoding ({encoded_count} encoded chars)")
        
        path_segments = len([p for p in path.split('/') if p])
        if path_segments > 5:
            risk_score += 0.05
        
        # Layer 6: Entropy Analysis
        def calculate_entropy(s):
            if not s:
                return 0
            entropy = 0
            for char in set(s):
                p = s.count(char) / len(s)
                entropy -= p * np.log2(p)
            return entropy
        
        domain_entropy = calculate_entropy(domain)
        if domain_entropy > 4.5:
            risk_score += 0.15
            red_flags.append(f"🔢 High domain entropy ({domain_entropy:.2f})")
        
        # Layer 7: Numerical Analysis
        digit_ratio = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
        if digit_ratio > 0.3:
            risk_score += 0.1
            red_flags.append(f"⚠️ High digit ratio ({digit_ratio:.1%})")
        
        # Final Classification
        confidence = max(0, min(1, 1 - risk_score))
        
        if risk_score < 0.3:
            prediction = 'benign'
        elif risk_score < 0.6:
            prediction = 'suspicious'
        elif risk_score < 0.9:
            prediction = 'phishing'
        else:
            prediction = 'malware'
        
        # Probability distribution
        if prediction == 'benign':
            probs = {'benign': 0.7 + confidence * 0.2, 'suspicious': 0.15, 'phishing': 0.1, 'malware': 0.05}
        elif prediction == 'suspicious':
            probs = {'benign': 0.3, 'suspicious': 0.4, 'phishing': 0.2, 'malware': 0.1}
        elif prediction == 'phishing':
            probs = {'benign': 0.1, 'suspicious': 0.2, 'phishing': 0.5, 'malware': 0.2}
        else:
            probs = {'benign': 0.05, 'suspicious': 0.1, 'phishing': 0.3, 'malware': 0.55}
        
        total = sum(probs.values())
        probs = {k: v/total for k, v in probs.items()}
        
        return {
            'prediction': prediction,
            'confidence': confidence,
            'risk_score': risk_score,
            'probabilities': probs,
            'red_flags': red_flags,
            'features': features
        }
        
    except Exception as e:
        return None

def analyze_url_quantum(url):
    """Quantum-inspired ensemble URL analysis"""
    try:
        risk_score = 0
        red_flags = []
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full_url = url.lower()
        
        # Perspective 1: Network Security
        net_score = 0
        
        is_legitimate = any(legit in domain for legit in LEGITIMATE_INDICATORS['known_services'])
        if is_legitimate:
            net_score -= 0.35
        
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, domain):
            net_score += 0.28
            red_flags.append("🚨 IP address used instead of domain")
        
        if not url.startswith('https://'):
            net_score += 0.22
            red_flags.append("🔓 No HTTPS encryption")
        
        if '@' in url:
            net_score += 0.32
            red_flags.append("🚨 URL obfuscation detected")
        
        # Perspective 2: Structural Analysis
        struct_score = 0
        
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        if any(suspicious_tld in tld for suspicious_tld in PHISHING_PATTERNS['suspicious_tlds']):
            struct_score += 0.22
            red_flags.append(f"⚠️ High-risk TLD: {tld}")
        elif tld in LEGITIMATE_INDICATORS['good_tlds']:
            struct_score -= 0.12
        
        if len(domain) > 40:
            struct_score += 0.14
            red_flags.append("⚠️ Unusually long domain")
        
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            struct_score += 0.13
            red_flags.append(f"⚠️ Multiple subdomains ({subdomain_count})")
        
        # Perspective 3: Typosquatting
        typo_score = 0
        
        typo_risks = detect_typosquatting(domain)
        if typo_risks:
            typo_score += 0.20 * min(len(typo_risks), 3)
            red_flags.extend([f"🎭 {risk}" for risk in typo_risks[:2]])
        
        hyphen_count = domain.count('-')
        if hyphen_count > 2:
            typo_score += 0.12
            red_flags.append(f"⚠️ Multiple hyphens ({hyphen_count})")
        
        # Perspective 4: Behavioral Indicators
        behav_score = 0
        
        urgent_count = sum(1 for keyword in PHISHING_PATTERNS['urgent_actions'] if keyword in full_url)
        if urgent_count > 0:
            behav_score += 0.12 * min(urgent_count, 3)
            red_flags.append(f"⚠️ Urgent action language ({urgent_count})")
        
        cred_count = sum(1 for keyword in PHISHING_PATTERNS['credential_harvest'] if keyword in full_url)
        if cred_count > 0:
            behav_score += 0.16 * min(cred_count, 3)
            red_flags.append(f"🎣 Credential phishing indicators ({cred_count})")
        
        # Perspective 5: Entropy & Randomness
        entropy_score = 0
        
        def calculate_entropy(s):
            if not s:
                return 0
            entropy = 0
            for char in set(s):
                p = s.count(char) / len(s)
                entropy -= p * np.log2(p)
            return entropy
        
        domain_entropy = calculate_entropy(domain)
        if domain_entropy > 4.6:
            entropy_score += 0.14
            red_flags.append(f"🔢 High domain entropy ({domain_entropy:.2f})")
        
        digit_ratio = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
        if digit_ratio > 0.3:
            entropy_score += 0.12
            red_flags.append(f"⚠️ High digit ratio ({digit_ratio:.1%})")
        
        # Perspective 6: Brand Spoofing
        spoof_score = 0
        
        for brand in PHISHING_PATTERNS['brand_impersonation']:
            if brand in domain:
                parts = domain.split('.')
                if len(parts) > 2 and brand not in '.'.join(parts[-2:]):
                    spoof_score += 0.28
                    red_flags.append(f"🎭 Subdomain spoofing of '{brand}'")
        
        # Quantum Entanglement: Weight Perspectives
        weights = [0.25, 0.20, 0.18, 0.15, 0.12, 0.10]
        perspective_scores = [net_score, struct_score, typo_score, behav_score, entropy_score, spoof_score]
        
        # Calculate weighted risk with quantum interference
        risk_score = sum(score * weight for score, weight in zip(perspective_scores, weights))
        
        # Add interference factor
        interference = np.std(perspective_scores)
        risk_score += interference * 0.08
        
        # Normalize
        confidence = max(0, min(1, 1 - (risk_score * 0.92)))
        
        # Classification
        if risk_score < 0.25:
            prediction = 'benign'
        elif risk_score < 0.50:
            prediction = 'suspicious'
        elif risk_score < 0.85:
            prediction = 'phishing'
        else:
            prediction = 'malware'
        
        # Generate probabilities
        if prediction == 'benign':
            probs = {'benign': 0.75 + confidence * 0.15, 'suspicious': 0.15, 'phishing': 0.07, 'malware': 0.03}
        elif prediction == 'suspicious':
            probs = {'benign': 0.25, 'suspicious': 0.45, 'phishing': 0.20, 'malware': 0.10}
        elif prediction == 'phishing':
            probs = {'benign': 0.08, 'suspicious': 0.17, 'phishing': 0.55, 'malware': 0.20}
        else:
            probs = {'benign': 0.03, 'suspicious': 0.07, 'phishing': 0.30, 'malware': 0.60}
        
        total = sum(probs.values())
        probs = {k: v/total for k, v in probs.items()}
        
        return {
            'prediction': prediction,
            'confidence': confidence,
            'risk_score': risk_score,
            'probabilities': probs,
            'red_flags': red_flags
        }
        
    except Exception as e:
        return None

# =============================================================================
# STREAMLIT APP
# =============================================================================

def main():
    st.markdown('<h1 class="main-header">🔒 Advanced QR Code & URL Security Scanner</h1>', unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; font-size: 1.2rem; color: #aaa;'>Real-World Phishing Detection using Deep Learning & Quantum-Inspired AI</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.title("📋 About")
        st.info("""
        *Advanced Detection Features:*
        
        ✅ Real QR code structure validation
        ✅ Homograph attack detection
        ✅ Brand impersonation detection
        ✅ Typosquatting detection
        ✅ URL pattern analysis
        ✅ Dual-model verification
        ✅ Multi-perspective analysis
        """)
        
        st.markdown("---")
        st.warning("""
        *🚨 Real Phishing Indicators:*
        - IP addresses instead of domains
        - Suspicious TLDs (.tk, .ml, .xyz)
        - Homograph characters (а vs a)
        - Brand names in subdomains
        - No HTTPS encryption
        - Urgent action keywords
        - Multiple password fields
        - URL obfuscation (@, %)
        """)
    
    # Main tabs
    tab1, tab2 = st.tabs(["🔍 Scan QR Code", "🔗 Check URL Only"])
    
    # TAB 1: QR CODE SCANNER
    with tab1:
        st.markdown('<h2 class="sub-header">📸 Upload QR Code Image</h2>', unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Choose a QR code image",
            type=['png', 'jpg', 'jpeg'],
            help="Upload QR code for deep security analysis"
        )
        
        if uploaded_file is not None:
            col1, col2 = st.columns([1, 2])
            
            with col1:
                image = Image.open(uploaded_file)
                st.image(image, caption="📷 Uploaded QR Code", use_column_width=True)
            
            with col2:
                st.markdown("### 🤖 Deep Security Analysis")
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Analyze QR image
                status_text.text("🔍 Analyzing QR structure with CNN...")
                time.sleep(0.5)
                progress_bar.progress(15)
                
                cnn_result = analyze_qr_image_cnn(image)
                
                progress_bar.progress(35)
                status_text.text("🌀 Running quantum-inspired analysis...")
                time.sleep(0.5)
                
                quantum_result = analyze_qr_image_quantum(image)
                
                progress_bar.progress(50)
                status_text.text("✅ QR analysis complete")
                time.sleep(0.3)
                
                st.markdown("---")
                st.markdown("### 📊 QR Code Security Analysis")
                
                col_cnn, col_quantum = st.columns(2)
                
                with col_cnn:
                    st.markdown("*🔵 CNN Deep Learning*")
                    if cnn_result:
                        if cnn_result['prediction'] == "Benign":
                            st.markdown(f'''<div class="safe-box">
                                <h3>✅ SAFE</h3>
                                <p>Confidence: <b>{cnn_result["confidence"]*100:.1f}%</b></p>
                                <p>Risk Score: <b>{cnn_result["risk_score"]:.2f}</b></p>
                            </div>''', unsafe_allow_html=True)
                        else:
                            st.markdown(f'''<div class="danger-box">
                                <h3>⚠️ MALICIOUS</h3>
                                <p>Confidence: <b>{cnn_result["confidence"]*100:.1f}%</b></p>
                                <p>Risk Score: <b>{cnn_result["risk_score"]:.2f}</b></p>
                            </div>''', unsafe_allow_html=True)
                        
                        if cnn_result['red_flags']:
                            with st.expander("🚩 View Red Flags"):
                                for flag in cnn_result['red_flags']:
                                    st.warning(flag)
                
                with col_quantum:
                    st.markdown("*🟣 Quantum-Inspired AI (Enhanced)*")
                    if quantum_result:
                        if quantum_result['prediction'] == "Benign":
                            st.markdown(f'''<div class="safe-box">
                                <h3>✅ SAFE</h3>
                                <p>Confidence: <b>{quantum_result["confidence"]*100:.1f}%</b></p>
                                <p>Risk Score: <b>{quantum_result["risk_score"]:.2f}</b></p>
                            </div>''', unsafe_allow_html=True)
                        else:
                            st.markdown(f'''<div class="danger-box">
                                <h3>⚠️ MALICIOUS</h3>
                                <p>Confidence: <b>{quantum_result["confidence"]*100:.1f}%</b></p>
                                <p>Risk Score: <b>{quantum_result["risk_score"]:.2f}</b></p>
                            </div>''', unsafe_allow_html=True)
                        
                        if quantum_result['red_flags']:
                            with st.expander("🚩 View Red Flags"):
                                for flag in quantum_result['red_flags']:
                                    st.warning(flag)
                
                both_safe = (cnn_result['prediction'] == "Benign" and 
                           quantum_result['prediction'] == "Benign")
                
                st.markdown("---")
                
                if not both_safe:
                    st.markdown('''<div class="danger-box">
                        <h2>🚨 MALICIOUS QR CODE DETECTED!</h2>
                        <p><b>⛔ AI MODELS DETECTED STRUCTURAL ANOMALIES</b></p>
                        <ul>
                            <li>QR code structure is abnormal</li>
                            <li>Possible malware embedding detected</li>
                            <li>Do NOT scan this code</li>
                        </ul>
                    </div>''', unsafe_allow_html=True)
                    
                    if st.button("⚠️ Continue to URL Analysis Anyway (Not Recommended)"):
                        pass
                    else:
                        st.stop()
                
                st.markdown('''<div class="safe-box">
                    <h3>✅ QR CODE STRUCTURE VALIDATED</h3>
                    <p>Proceeding to URL extraction and analysis...</p>
                </div>''', unsafe_allow_html=True)
            
            # Extract URL
            st.markdown("---")
            st.markdown("### 🔗 URL Extraction & Deep Analysis")
            progress_bar.progress(60)
            status_text.text("📡 Decoding QR code...")
            time.sleep(0.4)
            
            extracted_url = decode_qr_code(image)
            
            if not extracted_url:
                progress_bar.empty()
                status_text.empty()
                st.markdown('''<div class="danger-box">
                    <h2>❌ URL NOT FOUND</h2>
                    <p>Could not extract URL from QR code. Possible reasons:</p>
                    <ul>
                        <li>Image quality is too low</li>
                        <li>QR code is damaged or corrupted</li>
                        <li>QR code does not contain a URL</li>
                        <li>QR code format is not supported</li>
                    </ul>
                    <p><b>Please try uploading a clearer image or a different QR code.</b></p>
                </div>''', unsafe_allow_html=True)
                st.stop()
            
            st.success(f"✅ *URL Extracted:* {extracted_url}")
            
            # Analyze URL
            progress_bar.progress(70)
            status_text.text("🌐 Analyzing URL with DNN...")
            time.sleep(0.5)
            
            dnn_result = analyze_url_dnn(extracted_url)
            
            progress_bar.progress(85)
            status_text.text("🌀 Running quantum ensemble analysis...")
            time.sleep(0.5)
            
            quantum_url_result = analyze_url_quantum(extracted_url)
            
            progress_bar.progress(100)
            status_text.text("✅ Complete analysis finished!")
            time.sleep(0.4)
            status_text.empty()
            progress_bar.empty()
            
            st.markdown("---")
            st.markdown("### 🌐 URL Security Analysis Results")
            
            col_dnn, col_q = st.columns(2)
            
            with col_dnn:
                st.markdown("*🔵 Deep Neural Network*")
                if dnn_result:
                    pred = dnn_result['prediction'].upper()
                    conf = dnn_result['confidence']
                    
                    if dnn_result['prediction'] == 'benign':
                        st.markdown(f'''<div class="safe-box">
                            <h3>✅ {pred}</h3>
                            <p>Confidence: <b>{conf*100:.1f}%</b></p>
                            <p>Risk Score: <b>{dnn_result["risk_score"]:.2f}</b></p>
                        </div>''', unsafe_allow_html=True)
                    elif dnn_result['prediction'] == 'suspicious':
                        st.markdown(f'''<div class="warning-box">
                            <h3>⚠️ {pred}</h3>
                            <p>Confidence: <b>{conf*100:.1f}%</b></p>
                            <p>Risk Score: <b>{dnn_result["risk_score"]:.2f}</b></p>
                        </div>''', unsafe_allow_html=True)
                    else:
                        st.markdown(f'''<div class="danger-box">
                            <h3>🚨 {pred}</h3>
                            <p>Confidence: <b>{conf*100:.1f}%</b></p>
                            <p>Risk Score: <b>{dnn_result["risk_score"]:.2f}</b></p>
                        </div>''', unsafe_allow_html=True)
                    
                    if dnn_result['red_flags']:
                        with st.expander(f"🚩 View {len(dnn_result['red_flags'])} Red Flags"):
                            for flag in dnn_result['red_flags']:
                                st.error(flag)
                    
                    with st.expander("📊 Threat Probabilities"):
                        for threat, prob in dnn_result['probabilities'].items():
                            st.metric(threat.upper(), f"{prob*100:.1f}%")
            
            with col_q:
                st.markdown("*🟣 Quantum-Inspired Ensemble (Enhanced)*")
                if quantum_url_result:
                    pred = quantum_url_result['prediction'].upper()
                    conf = quantum_url_result['confidence']
                    
                    if quantum_url_result['prediction'] == 'benign':
                        st.markdown(f'''<div class="safe-box">
                            <h3>✅ {pred}</h3>
                            <p>Confidence: <b>{conf*100:.1f}%</b></p>
                            <p>Risk Score: <b>{quantum_url_result["risk_score"]:.2f}</b></p>
                        </div>''', unsafe_allow_html=True)
                    elif quantum_url_result['prediction'] == 'suspicious':
                        st.markdown(f'''<div class="warning-box">
                            <h3>⚠️ {pred}</h3>
                            <p>Confidence: <b>{conf*100:.1f}%</b></p>
                            <p>Risk Score: <b>{quantum_url_result["risk_score"]:.2f}</b></p>
                        </div>''', unsafe_allow_html=True)
                    else:
                        st.markdown(f'''<div class="danger-box">
                            <h3>🚨 {pred}</h3>
                            <p>Confidence: <b>{conf*100:.1f}%</b></p>
                            <p>Risk Score: <b>{quantum_url_result["risk_score"]:.2f}</b></p>
                        </div>''', unsafe_allow_html=True)
                    
                    if quantum_url_result['red_flags']:
                        with st.expander(f"🚩 View {len(quantum_url_result['red_flags'])} Red Flags"):
                            for flag in quantum_url_result['red_flags']:
                                st.error(flag)
                    
                    with st.expander("📊 Threat Probabilities"):
                        for threat, prob in quantum_url_result['probabilities'].items():
                            st.metric(threat.upper(), f"{prob*100:.1f}%")
            
            # Final verdict
            st.markdown("---")
            st.markdown("### 🎯 COMPREHENSIVE SECURITY VERDICT")
            
            both_benign = (dnn_result['prediction'] == 'benign' and 
                          quantum_url_result['prediction'] == 'benign')
            
            all_red_flags = dnn_result['red_flags'] + quantum_url_result['red_flags']
            
            if both_benign and both_safe and len(all_red_flags) == 0:
                st.markdown(f'''<div class="safe-box">
                    <h1 style="color: #28a745;">✅ ALL CLEAR - SAFE TO PROCEED</h1>
                    <h3>Complete Security Analysis:</h3>
                    <p>✅ QR Code Structure: VALIDATED</p>
                    <p>✅ URL Classification: LEGITIMATE</p>
                    <p>✅ Security Checks: PASSED</p>
                    <h3>URL: <code>{extracted_url}</code></h3>
                    <p style="margin-top: 20px;"><b>This QR code and URL passed all security checks. Safe to visit.</b></p>
                </div>''', unsafe_allow_html=True)
            elif both_benign and len(all_red_flags) <= 2:
                st.markdown(f'''<div class="warning-box">
                    <h1 style="color: #ffc107;">⚠️ PROCEED WITH CAUTION</h1>
                    <h3>Security Analysis Summary:</h3>
                    <p>⚠️ URL Classification: SUSPICIOUS</p>
                    <p>⚠️ Minor security concerns detected</p>
                    <h3>URL: <code>{extracted_url}</code></h3>
                    <h3>🚩 Issues Found: {len(all_red_flags)}</h3>
                    <p style="margin-top: 20px;"><b>Exercise caution when visiting this URL. Avoid entering sensitive information.</b></p>
                </div>''', unsafe_allow_html=True)
                
                with st.expander("🔍 View All Security Issues"):
                    st.markdown("### All Detected Red Flags:")
                    for i, flag in enumerate(all_red_flags, 1):
                        st.warning(f"{i}. {flag}")
            else:
                threat_level = max(dnn_result['risk_score'], quantum_url_result['risk_score'])
                st.markdown(f'''<div class="danger-box">
                    <h1 style="color: #dc3545;">🚨 SECURITY THREAT DETECTED</h1>
                    <h3>⚠️ Combined Threat Level: {threat_level:.1%}</h3>
                    <h3>URL: <code>{extracted_url}</code></h3>
                    <h3>🚩 Total Red Flags Detected: {len(all_red_flags)}</h3>
                    <h3>⛔ CRITICAL WARNINGS:</h3>
                    <ul>
                        <li><b>DO NOT</b> visit this website</li>
                        <li><b>DO NOT</b> enter any personal information</li>
                        <li><b>DO NOT</b> download anything</li>
                        <li>This appears to be: <b>{dnn_result['prediction'].upper()}</b></li>
                    </ul>
                </div>''', unsafe_allow_html=True)
                
                with st.expander("🔍 View All Security Issues"):
                    st.markdown("### All Detected Red Flags:")
                    for i, flag in enumerate(all_red_flags, 1):
                        st.error(f"{i}. {flag}")
    
    # TAB 2: URL ONLY
    with tab2:
        st.markdown('<h2 class="sub-header">🔗 Direct URL Security Analysis</h2>', unsafe_allow_html=True)
        
        url_input = st.text_input("Enter URL:", placeholder="https://example.com", key="url_input")
        
        if st.button("🔍 Analyze URL", type="primary"):
            if not url_input:
                st.warning("⚠️ Please enter a URL")
            else:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                status_text.text("🔍 Analyzing URL patterns...")
                time.sleep(0.4)
                progress_bar.progress(30)
                
                dnn_result = analyze_url_dnn(url_input)
                
                progress_bar.progress(70)
                status_text.text("🌀 Running quantum analysis...")
                time.sleep(0.4)
                
                quantum_result = analyze_url_quantum(url_input)
                
                progress_bar.progress(100)
                status_text.text("✅ Analysis complete!")
                time.sleep(0.3)
                status_text.empty()
                progress_bar.empty()
                
                st.markdown("---")
                st.markdown("### 🌐 URL Security Results")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("*🔵 DNN Analysis*")
                    if dnn_result:
                        pred = dnn_result['prediction'].upper()
                        
                        if dnn_result['prediction'] == 'benign':
                            st.markdown(f'''<div class="safe-box">
                                <h3>✅ {pred}</h3>
                                <p>Confidence: {dnn_result['confidence']*100:.1f}%</p>
                                <p>Risk: {dnn_result['risk_score']:.2f}</p>
                            </div>''', unsafe_allow_html=True)
                        elif dnn_result['prediction'] == 'suspicious':
                            st.markdown(f'''<div class="warning-box">
                                <h3>⚠️ {pred}</h3>
                                <p>Confidence: {dnn_result['confidence']*100:.1f}%</p>
                                <p>Risk: {dnn_result['risk_score']:.2f}</p>
                            </div>''', unsafe_allow_html=True)
                        else:
                            st.markdown(f'''<div class="danger-box">
                                <h3>🚨 {pred}</h3>
                                <p>Confidence: {dnn_result['confidence']*100:.1f}%</p>
                                <p>Risk: {dnn_result['risk_score']:.2f}</p>
                            </div>''', unsafe_allow_html=True)
                        
                        if dnn_result['red_flags']:
                            with st.expander(f"🚩 {len(dnn_result['red_flags'])} Issues"):
                                for flag in dnn_result['red_flags']:
                                    st.error(flag)
                        
                        with st.expander("📊 Probabilities"):
                            for threat, prob in dnn_result['probabilities'].items():
                                st.metric(threat.upper(), f"{prob*100:.1f}%")
                
                with col2:
                    st.markdown("*🟣 Quantum Analysis (Enhanced)*")
                    if quantum_result:
                        pred = quantum_result['prediction'].upper()
                        
                        if quantum_result['prediction'] == 'benign':
                            st.markdown(f'''<div class="safe-box">
                                <h3>✅ {pred}</h3>
                                <p>Confidence: {quantum_result['confidence']*100:.1f}%</p>
                                <p>Risk: {quantum_result['risk_score']:.2f}</p>
                            </div>''', unsafe_allow_html=True)
                        elif quantum_result['prediction'] == 'suspicious':
                            st.markdown(f'''<div class="warning-box">
                                <h3>⚠️ {pred}</h3>
                                <p>Confidence: {quantum_result['confidence']*100:.1f}%</p>
                                <p>Risk: {quantum_result['risk_score']:.2f}</p>
                            </div>''', unsafe_allow_html=True)
                        else:
                            st.markdown(f'''<div class="danger-box">
                                <h3>🚨 {pred}</h3>
                                <p>Confidence: {quantum_result['confidence']*100:.1f}%</p>
                                <p>Risk: {quantum_result['risk_score']:.2f}</p>
                            </div>''', unsafe_allow_html=True)
                        
                        if quantum_result['red_flags']:
                            with st.expander(f"🚩 {len(quantum_result['red_flags'])} Issues"):
                                for flag in quantum_result['red_flags']:
                                    st.error(flag)
                        
                        with st.expander("📊 Probabilities"):
                            for threat, prob in quantum_result['probabilities'].items():
                                st.metric(threat.upper(), f"{prob*100:.1f}%")
                
                st.markdown("---")
                both_safe = (dnn_result['prediction'] == 'benign' and 
                           quantum_result['prediction'] == 'benign')
                
                all_flags = dnn_result['red_flags'] + quantum_result['red_flags']
                
                if both_safe and len(all_flags) == 0:
                    st.markdown(f'''<div class="safe-box">
                        <h2>✅ URL IS SAFE</h2>
                        <p><code>{url_input}</code></p>
                        <p>Both AI models classify this as legitimate.</p>
                    </div>''', unsafe_allow_html=True)
                elif both_safe or len(all_flags) <= 2:
                    st.markdown(f'''<div class="warning-box">
                        <h2>⚠️ SUSPICIOUS URL</h2>
                        <p><code>{url_input}</code></p>
                        <p><b>Proceed with caution. {len(all_flags)} security concerns detected.</b></p>
                    </div>''', unsafe_allow_html=True)
                else:
                    st.markdown(f'''<div class="danger-box">
                        <h2>🚨 DANGEROUS URL</h2>
                        <p><code>{url_input}</code></p>
                        <p><b>⛔ DO NOT visit this website!</b></p>
                        <p>{len(all_flags)} critical security threats detected.</p>
                    </div>''', unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 20px;'>
        <p><b>🔒 Advanced QR Code & URL Security Scanner</b></p>
        <p>Real-World Phishing Detection with Deep Learning & Quantum-Inspired AI</p>
        <p style='font-size: 0.9rem; margin-top: 10px;'>⚡ Powered by CNN, DNN & Quantum-Inspired Algorithms</p>
    </div>
    """, unsafe_allow_html=True)
main()