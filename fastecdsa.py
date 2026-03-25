"""
Certificateless Hybrid Signcryption Scheme Implementation
Using fastecdsa for Elliptic Curve operations
"""

import os
import time
import hashlib
import hmac
from typing import Tuple, Dict, Any, Optional
from dataclasses import dataclass
from fastecdsa import curve, keys
from fastecdsa.point import Point
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


@dataclass
class SystemParameters:
    """System parameters for the certificateless signcryption scheme"""
    curve: Any  # Elliptic curve
    G: Point    # Generator point
    q: int      # Field order
    P_pub: Point  # Master public key


@dataclass
class KeyPair:
    """Key pair for a participant"""
    ID: str           # Participant's identity
    t: int            # Secret value
    T: Point          # Public value T = t*G
    D: int            # Partial private key
    R: Point          # Public value R
    private_key: Tuple[int, int]  # (t, D)
    public_key: Tuple[Point, Point]  # (T, R)


@dataclass
class Ciphertext:
    """Ciphertext structure for the signcryption scheme"""
    beta: Point       # Signature component
    U: Point          # Key encapsulation component
    V: Point          # Key encapsulation component
    F: int            # Signature factor
    h: int            # Hash value for signature
    encrypted_data: bytes  # Encrypted data


class CertificatelessSigncryption:
    """Implementation of Certificateless Hybrid Signcryption Scheme"""

    def __init__(self):
        """Initialize with NIST P-256 curve"""
        self.curve = curve.P256
        self.G = self.curve.G
        self.q = self.curve.q
        # Master secret key and public parameters will be set in setup

    def H1(self, ID: str, R: Point) -> int:
        """Hash function H1: {0,1}* -> Z_q*"""
        data = f"{ID}|{R.x}|{R.y}".encode()
        return int(hashlib.sha256(data).hexdigest(), 16) % self.q

    def H2(self, U: Point, V: Point, ID_u: str, ID_r: str) -> bytes:
        """Hash function H2: {0,1}* -> {0,1}^256"""
        data = f"{U.x}|{U.y}|{V.x}|{V.y}|{ID_u}|{ID_r}".encode()
        return hashlib.sha256(data).digest()

    def H3(self, tau: bytes, ID_u: str, ID_r: str, R_u: Point, R_r: Point, 
           P_u: Tuple[Point, Point], P_r: Tuple[Point, Point], beta: Point, 
           U: Point, V: Point) -> int:
        """Hash function H3: {0,1}* -> Z_q*"""
        T_u, _ = P_u
        T_r, _ = P_r
        data = (f"{tau.hex()}|{ID_u}|{ID_r}|{R_u.x}|{R_u.y}|{R_r.x}|{R_r.y}|"
                f"{T_u.x}|{T_u.y}|{T_r.x}|{T_r.y}|{beta.x}|{beta.y}|"
                f"{U.x}|{U.y}|{V.x}|{V.y}").encode()
        return int(hashlib.sha256(data).hexdigest(), 16) % self.q

    def global_setup(self) -> SystemParameters:
        """GlobalSetup algorithm - Initialize system parameters"""
        start_time = time.time()
        
        # Generate master secret key
        x = keys.gen_private_key(self.curve)
        # Compute master public key
        P_pub = x * self.G
        
        params = SystemParameters(
            curve=self.curve,
            G=self.G,
            q=self.q,
            P_pub=P_pub
        )
        
        self.params = params
        self.master_secret = x
        
        elapsed = time.time() - start_time
        print(f"GlobalSetup executed in {elapsed:.6f} seconds")
        return params

    def participant_key_gen(self, ID: str) -> Tuple[int, Point]:
        """P_Keygen algorithm - Generate participant's secret and public value"""
        start_time = time.time()
        
        # Generate participant's secret value
        t = keys.gen_private_key(self.curve)
        # Compute corresponding public value
        T = t * self.G
        
        elapsed = time.time() - start_time
        print(f"P_Keygen executed in {elapsed:.6f} seconds for {ID}")
        return t, T

    def extract(self, ID: str, T: Point) -> Tuple[int, Point]:
        """Extract algorithm - Generate partial private key for a participant"""
        start_time = time.time()
        
        # Generate random value
        r = keys.gen_private_key(self.curve)
        # Compute R
        R = r * self.G
        # Compute h = H1(ID, R)
        h = self.H1(ID, R)
        # Compute partial private key D = r + x*h
        D = (r + self.master_secret * h) % self.q
        
        elapsed = time.time() - start_time
        print(f"Extract executed in {elapsed:.6f} seconds for {ID}")
        return D, R

    def key_setup(self, ID: str, t: int, D: int, T: Point, R: Point) -> KeyPair:
        """Key_Setup algorithm - Establish full key pair for a participant"""
        start_time = time.time()
        
        # Combine components to create the full key pair
        private_key = (t, D)
        public_key = (T, R)
        
        key_pair = KeyPair(
            ID=ID,
            t=t,
            T=T,
            D=D,
            R=R,
            private_key=private_key,
            public_key=public_key
        )
        
        elapsed = time.time() - start_time
        print(f"Key_Setup executed in {elapsed:.6f} seconds for {ID}")
        return key_pair

    def sym_keygen(self, ID_u: str, P_u: Tuple[Point, Point], S_u: Tuple[int, int], 
                 ID_r: str, P_r: Tuple[Point, Point]) -> Tuple[bytes, Dict]:
        """Sym_keygen algorithm - Generate symmetric key for encryption"""
        start_time = time.time()
        
        # Parse inputs
        T_u, R_u = P_u
        t_u, D_u = S_u
        T_r, R_r = P_r
        
        # Generate random value alpha
        alpha = keys.gen_private_key(self.curve)
        # Compute U = alpha * G
        U = alpha * self.G
        # Compute V = alpha * (R_r + H1(ID_r, R_r) * P_pub + T_r)
        h_r = self.H1(ID_r, R_r)
        V = alpha * (R_r + h_r * self.params.P_pub + T_r)
        # Generate symmetric key K = H2(U, V, ID_u, ID_r)
        K = self.H2(U, V, ID_u, ID_r)
        
        # Create state information phi
        phi = {
            'alpha': alpha,
            'ID_u': ID_u,
            'P_u': P_u,
            'S_u': S_u,
            'ID_r': ID_r,
            'P_r': P_r,
            'U': U,
            'V': V,
            'R_u': R_u,
            'R_r': R_r  # Store R_r to use in cl_encaps
        }
        
        elapsed = time.time() - start_time
        print(f"Sym_keygen executed in {elapsed:.6f} seconds")
        return K, phi

    def cl_encaps(self, phi: Dict, tau: bytes) -> Tuple[Point, int, int]:
        """CL-Encaps algorithm - Generate encapsulation"""
        start_time = time.time()
        
        # Parse state information
        alpha = phi['alpha']
        ID_u = phi['ID_u']
        P_u = phi['P_u']
        S_u = phi['S_u']
        ID_r = phi['ID_r']
        P_r = phi['P_r']
        U = phi['U']
        V = phi['V']
        R_u = phi['R_u']
        R_r = phi['R_r']
        
        T_u, _ = P_u
        t_u, D_u = S_u
        
        # Generate random value l
        l = keys.gen_private_key(self.curve)
        # Compute beta = l * G
        beta = l * self.G
        # Compute hash h
        h = self.H3(tau, ID_u, ID_r, R_u, R_r, P_u, P_r, beta, U, V)
        # Compute signature factor F = l / (h*t_u + D_u)
        F = (l * pow(h * t_u + D_u, -1, self.q)) % self.q
        
        elapsed = time.time() - start_time
        print(f"CL-Encaps executed in {elapsed:.6f} seconds")
        return beta, F, h

    def cl_decaps(self, gamma: Tuple, tau: bytes, ID_u: str, P_u: Tuple[Point, Point], 
                ID_r: str, S_r: Tuple[int, int], P_r: Tuple[Point, Point]) -> Optional[bytes]:
        """CL-Decaps algorithm - Verify and recover the symmetric key"""
        start_time = time.time()
        
        # Parse inputs
        beta, U, V, F, h = gamma
        T_u, R_u = P_u
        T_r, R_r = P_r  # Use the actual R_r from P_r
        t_r, D_r = S_r
        
        # Compute W = V / (D_r + t_r)
        try:
            inverse_scalar = pow(D_r + t_r, -1, self.q)
            W = inverse_scalar * V
        except ValueError:
            print("Key recovery verification failed: Invalid inverse calculation")
            elapsed = time.time() - start_time
            print(f"CL-Decaps executed in {elapsed:.6f} seconds (failed)")
            return None
        
        # Verify W = U
        if (W.x != U.x or W.y != U.y):
            print(f"Key recovery verification failed: W({W.x}, {W.y}) != U({U.x}, {U.y})")
            elapsed = time.time() - start_time
            print(f"CL-Decaps executed in {elapsed:.6f} seconds (failed)")
            return None
        
        # Recompute hash h'
        h_prime = self.H3(tau, ID_u, ID_r, R_u, R_r, P_u, P_r, beta, U, V)
        
        # Verify h = h'
        if h != h_prime:
            print(f"Signature verification failed: h({h}) != h'({h_prime})")
            elapsed = time.time() - start_time
            print(f"CL-Decaps executed in {elapsed:.6f} seconds (failed)")
            return None
        
        # Verify signature equation: F * (h*T_u + R_u + H1(ID_u, R_u)*P_pub) = beta
        h_u = self.H1(ID_u, R_u)
        verification_point = F * (h * T_u + R_u + h_u * self.params.P_pub)
        
        if (verification_point.x != beta.x or verification_point.y != beta.y):
            print("Signature verification failed: Verification equation doesn't hold")
            elapsed = time.time() - start_time
            print(f"CL-Decaps executed in {elapsed:.6f} seconds (failed)")
            return None
        
        # Derive symmetric key
        K = self.H2(U, V, ID_u, ID_r)
        
        elapsed = time.time() - start_time
        print(f"CL-Decaps executed in {elapsed:.6f} seconds (successful)")
        return K

    def aes_encrypt(self, key: bytes, data: bytes) -> bytes:
        """AES encryption for Data Encapsulation Mechanism (DEM)"""
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ciphertext

    def aes_decrypt(self, key: bytes, data: bytes) -> bytes:
        """AES decryption for Data Encapsulation Mechanism (DEM)"""
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

    def signcrypt(self, data: bytes, ID_u: str, P_u: Tuple[Point, Point], 
                 S_u: Tuple[int, int], ID_r: str, P_r: Tuple[Point, Point]) -> Ciphertext:
        """Signcrypt algorithm - Generate signcryption of a message"""
        start_time = time.time()
        
        # Generate symmetric key
        K, phi = self.sym_keygen(ID_u, P_u, S_u, ID_r, P_r)
        
        # Encrypt data using AES (DEM)
        c = self.aes_encrypt(K, data)
        
        # Generate encapsulation
        beta, F, h = self.cl_encaps(phi, c)
        
        # Construct ciphertext
        ciphertext = Ciphertext(
            beta=beta,
            U=phi['U'],
            V=phi['V'],
            F=F,
            h=h,
            encrypted_data=c
        )
        
        elapsed = time.time() - start_time
        print(f"Signcrypt executed in {elapsed:.6f} seconds")
        print(f"  - Data size: {len(data)} bytes")
        print(f"  - Ciphertext size: {len(c)} bytes")
        
        return ciphertext

    def unsigncrypt(self, ciphertext: Ciphertext, ID_u: str, P_u: Tuple[Point, Point], 
                  ID_r: str, P_r: Tuple[Point, Point], S_r: Tuple[int, int]) -> Optional[bytes]:
        """Unsigncrypt algorithm - Verify and decrypt a signcryption"""
        start_time = time.time()
        
        # Parse ciphertext
        gamma = (ciphertext.beta, ciphertext.U, ciphertext.V, ciphertext.F, ciphertext.h)
        c = ciphertext.encrypted_data
        
        # Recover symmetric key
        K = self.cl_decaps(gamma, c, ID_u, P_u, ID_r, S_r, P_r)
        
        if K is None:
            print("Unsigncryption failed: Could not recover symmetric key")
            elapsed = time.time() - start_time
            print(f"Unsigncrypt executed in {elapsed:.6f} seconds (failed)")
            return None
        
        # Decrypt the data
        try:
            data = self.aes_decrypt(K, c)
            elapsed = time.time() - start_time
            print(f"Unsigncrypt executed in {elapsed:.6f} seconds (successful)")
            print(f"  - Ciphertext size: {len(c)} bytes")
            print(f"  - Recovered data size: {len(data)} bytes")
            return data
        except Exception as e:
            print(f"Decryption error: {e}")
            elapsed = time.time() - start_time
            print(f"Unsigncrypt executed in {elapsed:.6f} seconds (failed)")
            return None


def run_performance_test(data_sizes=[1024, 10240, 102400, 1024000]):
    """Run performance tests with different data sizes"""
    print("\n" + "="*70)
    print("CERTIFICATELESS HYBRID SIGNCRYPTION PERFORMANCE TEST")
    print("="*70)
    
    # Initialize the scheme
    cls = CertificatelessSigncryption()
    
    # Setup system parameters
    print("\nInitializing system parameters:")
    params = cls.global_setup()
    
    # Setup patient
    print("\nSetting up patient (sender):")
    patient_id = "patient@healthcare.org"
    t_u, T_u = cls.participant_key_gen(patient_id)
    D_u, R_u = cls.extract(patient_id, T_u)
    patient = cls.key_setup(patient_id, t_u, D_u, T_u, R_u)
    
    # Setup doctor
    print("\nSetting up doctor (receiver):")
    doctor_id = "doctor@hospital.com"
    t_r, T_r = cls.participant_key_gen(doctor_id)
    D_r, R_r = cls.extract(doctor_id, T_r)
    doctor = cls.key_setup(doctor_id, t_r, D_r, T_r, R_r)
    
    print("\nPerforming signcryption and unsigncryption with various data sizes:")
    results = []
    
    for size in data_sizes:
        print(f"\nTesting with data size: {size} bytes")
        # Generate random data
        data = os.urandom(size)
        
        # Measure signcryption time
        signcrypt_start = time.time()
        ciphertext = cls.signcrypt(
            data, 
            patient.ID, patient.public_key, patient.private_key,
            doctor.ID, doctor.public_key
        )
        signcrypt_time = time.time() - signcrypt_start
        
        # Measure unsigncryption time
        unsigncrypt_start = time.time()
        recovered_data = cls.unsigncrypt(
            ciphertext,
            patient.ID, patient.public_key,
            doctor.ID, doctor.public_key, doctor.private_key
        )
        unsigncrypt_time = time.time() - unsigncrypt_start
        
        # Verify correctness
        if recovered_data == data:
            print(f"Data recovery successful - {size} bytes")
        else:
            print(f"Data recovery failed - {size} bytes")
        
        results.append({
            'size': size,
            'signcrypt_time': signcrypt_time,
            'unsigncrypt_time': unsigncrypt_time,
            'total_time': signcrypt_time + unsigncrypt_time
        })
    
    # Print summary table
    print("\n" + "="*70)
    print("PERFORMANCE SUMMARY")
    print("="*70)
    print(f"{'Size (bytes)':<15} {'Signcrypt (s)':<15} {'Unsigncrypt (s)':<15} {'Total (s)':<15}")
    print("-"*70)
    for r in results:
        print(f"{r['size']:<15} {r['signcrypt_time']:<15.6f} {r['unsigncrypt_time']:<15.6f} {r['total_time']:<15.6f}")
    print("="*70)
    
    return results


if __name__ == "__main__":
    # Run the performance test
    run_performance_test()