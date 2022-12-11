
# This is the Curve25519 version1.1 of Verifiable Random Function(vrf) written
# by @Xiaoting ZHANG(https://github.com/greypreacher)
# About Curve25519, see https://en.wikipedia.org/wiki/Curve25519
# About the difference between Curve25519 and ed25519, see https://zhuanlan.zhihu.com/p/524180490

import time
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA512, SHA256
from ecpy.keys import ECPublicKey, ECPrivateKey
import Crypto.Random.random

class vrf:
    def __init__(self):
        self.cv = Curve.get_curve('Curve25519')
        self.G = self.cv.generator
        self.order = self.cv.order

    def setup(self):
        """ generate parameters g, h, \tilde{g} and \tilde{h}. g is the generator/basepoint
                    of the curve and the other three are randomly sampling from Curve25519.

            Args:
                None
        """
        num3, num4 = Crypto.Random.random.getrandbits(256), Crypto.Random.random.getrandbits(256)
        g2, h2 = self.G * num3, self.G * num4

        def hasher2(g, h, Gamma, Theta, S1, S2, T0, T1):
            """ Hash the incoming parameters and return a bytes.

                Args:
                    g     (Point)                 :generator of the curve
                    h     (Point)                 :a point on the curve
                    Gamma / pub_key (Point)       :public key of the client
                    Theta / tag (Point)           :tag of the proof
                    S1 (Point)                    :S1 = g * \alpha = g * z_l + pk * (-x)
                    S2 (Point)                    :S2 = h * \beta = h * z_r + tag * (-x)
                    T0 (Point)                    :T0 = \tilde{g} * t0 + \tilde{h} * tau0
                    T1 (Point)                    :T1 = \tilde{g} * t1 + \tilde{h} * tau1
            """
            size = 32
            hasher = SHA256
            x, y = (Gamma.W.x).to_bytes(size, 'big'), (Gamma.W.y).to_bytes(size, 'big')
            gx, gy = (g.x).to_bytes(size, 'big'), (g.y).to_bytes(size, 'big')
            hx, hy = (h.x).to_bytes(size, 'big'), (h.y).to_bytes(size, 'big')
            xS1, yS1 = (S1.x).to_bytes(size, 'big'), (S1.y).to_bytes(size, 'big')
            xS2, yS2 = (S2.x).to_bytes(size, 'big'), (S2.y).to_bytes(size, 'big')
            xT0, yT0 = (T0.x).to_bytes(size, 'big'), (T0.y).to_bytes(size, 'big')
            xT1, yT1 = (T1.x).to_bytes(size, 'big'), (T1.y).to_bytes(size, 'big')
            xtag, ytag = (Theta.x).to_bytes(size, 'big'), (Theta.y).to_bytes(size, 'big')
            hash_val = hasher.new(x)
            hash_val.update(gx + gy + hx + hy + y + xtag + ytag + xS1 + yS1 + xS2 + yS2 + xT0 + yT0 + xT1 + yT1)
            return hash_val.digest()

        return (g2, h2, hasher2)


    def prove(self, param, g, h, Gamma, Theta, gamma):
        """ the prove procedure, return a proof pi

            Args:
                param (tuple)         :\tilde{g} and \tlide{h} generated
                g     (Point)         :generator of the curve
                h     (Point)         :a point on the curve
                Gamma (Point)         :public key of the client
                Theta /tag (Point)    :tag of the proof
                gamma (Point)         :private key of the client
        """
        # Commit Phase
        g1, h1, g2, h2, hasher2 = g, h, param[0], param[1], param[2]
        alpha, beta = Crypto.Random.random.randrange(1, self.order-1), Crypto.Random.random.randrange(1, self.order-1)
        S1, S2 = g1 * alpha, h1 * beta
        gamma_reciprocal = pow(gamma.d, -1, self.order)

        def l(X):
            return alpha + gamma.d * X
        def r(X):
            return gamma_reciprocal * X + beta

        t0 = ( alpha * beta ) % self.order
        t1 = (alpha * gamma_reciprocal + beta * gamma.d) % self.order
        tau0, tau1 = Crypto.Random.random.randrange(1, self.order-1), Crypto.Random.random.randrange(1, self.order-1)
        T0 = g2 * t0 + h2 * tau0
        T1 = g2 * t1 + h2 * tau1

        # Challenge Phase
        # Gamma/tag = h1 * gamma_reciprocal
        x = hasher2(g, h, Gamma, Theta, S1, S2, T0, T1)
        x_num = int.from_bytes(x, 'big') % self.order

        # Response Phase
        z_tau = ( tau1 * x_num + tau0 ) % self.order
        z_l = l(x_num) % self.order
        z_r = r(x_num) % self.order # zr = ( 1 / sk ) * X + beta

        return (z_tau, z_l, z_r, x, T1)

    def verify(self, param, g, h, Gamma, Theta, pi):
        """ the verification procedure, return 1 or 0

            Args:
                param (tuple)                    :\tilde{g} and \tlide{h} generated
                g     (Point)                    :generator of the curve
                h     (Point)                    :a point on the curve
                Gamma / pub_key (ECPublicKey)    :public key of the client
                Theta (Point)                    :tag of the proof
                pi (tuple)                       :the proof pi generated in the prove procedure
        """
        g1, h1, g2, h2, hasher2 = g, h, param[0], param[1], param[2]
        z_tau, z_l, z_r, x, T1 = pi[0], pi[1], pi[2], pi[3], pi[4]
        x_num = int.from_bytes(x, 'big') % self.order
        S1 = g1 * z_l + Gamma.W * (-x_num)
        S2 = h1 * z_r + Theta * (-x_num)
        temp = ( z_l * z_r ) % self.order
        T0 = g2 * temp + h2 * z_tau + g2 * (-x_num * x_num) + T1 * (-x_num)
        temp_hash = hasher2(g1, h1, Gamma, Theta, S1, S2, T0, T1)
        if x == temp_hash:
            return 1
        else:
            return 0

class vrf_protocol(vrf):
    def param_gen(self):
        """ generate parameters using the super class.setup() and an additional hash func
            Args:
                None
        """
        g1 = self.G
        param_ = super().setup()

        def hasher0(X, U):
            """ Hash the incoming parameters and return a bytes.

                Args:
                    X     (bytes)                 :input message
                    U     (Point)                 :U = hasher1(vk, X) * (1/sk)
            """
            size = 32
            hasher = SHA256
            Ux, Uy = (U.x).to_bytes(size, 'big'), (U.y).to_bytes(size, 'big')
            hash_val = hasher.new(X)
            hash_val.update(Ux + Uy)
            return hash_val.digest()

        def hasher1(vk, X):
            """ Hash the incoming parameters and return a point.

                Args:
                    vk     (ECPublicKey)          :public key
                    X      (bytes)                :input message
            """
            size = 32
            hasher = SHA256
            vkx, vky = (vk.W.x).to_bytes(size, 'big'), (vk.W.y).to_bytes(size, 'big')
            hash_val = hasher.new(X)
            hash_val.update(vkx + vky)
            hash_val = hash_val.digest()
            hash_num = int.from_bytes(hash_val, 'big') % self.order
            result = vk.W * hash_num #result is a point on the curve
            return result

        return (g1, hasher0, hasher1, param_)

    def key_gen(self, pp):
        """ generate a private key using a random number and compute
                    public key as public key = G * private key

            Args:
                None
        """
        sk_num = Crypto.Random.random.randrange(1, self.order - 1)
        sk = ECPrivateKey(sk_num, self.cv)
        vk= ECPublicKey(self.G * sk.d)
        return vk, sk

    def eval(self, sk, vk, X, pp):
        """ the evaluation procedure, return tag Y and proof pi

            Args:
                sk (ECPrivateKey)               :private key of the client
                vk (ECPublicKey)                :public key of the client
                X (bytes)                       :message transformed to bytes
                pp (tuple)                      :(g1, h1, hasher0, hasher1, param_) generated in the param_gen procedure
        """
        g1, hasher0, hasher1, param_ = pp[0], pp[1], pp[2], pp[3]
        h1_reciprocal = pow(sk.d, -1, self.order)
        U = hasher1(vk, X) * h1_reciprocal
        rho = self.prove(param_, g1, hasher1(vk, X), vk, U, sk)
        Y = hasher0(X, U)
        pi = (U, rho)
        return (Y, pi)

    def verify2(self, pp, vk, X, Y, pi):
        """ the verification procedure, return 1 or 0

            Args:
                pp (tuple)                      :(g1, h1, hasher0, hasher1, param_) generated in the param_gen procedure
                vk (ECPublicKey)                :public key of the client
                X (bytes)                       :message transformed to bytes
                Y (Point)                       :H0(X, U)
                pi (tuple)                      :the proof pi = (U, rho) generated in the prove procedure
        """
        g1, hasher0, hasher1, param_ = pp[0], pp[1], pp[2], pp[3]
        U, rho = pi[0], pi[1]
        verify_result = super().verify(param_, g1, hasher1(vk, X), vk, U, rho)
        if verify_result == 1 and Y == hasher0(X, U):
            return 1
        else:
            return 0


if __name__ == "__main__":

    verifier = vrf_protocol()
    pp = verifier.param_gen()
    g1, hasher0, hasher1, param_ = pp[0], pp[1], pp[2], pp[3]
    vk, sk = verifier.key_gen(pp)
    msg = b"this is the message"
    eval_result = verifier.eval(sk, vk, msg, pp)
    Y, pi = eval_result[0], eval_result[1]
    verify2_result = verifier.verify2(pp, vk, msg, Y, pi)
    print(verify2_result)

    '''
    t1 = time.perf_counter()
    vrf_count = []
    for i in range(1000):
        verifier = vrf_protocol()
        vrf_count.append(verifier)
        pp = verifier.param_gen()
        vk, sk = verifier.key_gen(pp)
        msg = b"this is the message"
        eval_result = verifier.eval(sk, vk, msg, pp)
        Y, pi = eval_result[0], eval_result[1]
        verify2_result = verifier.verify2(pp, vk, msg, Y, pi)
        if verify2_result == 1:
            print('valid in the ' + str(i + 1) + ' test')
            # logging.info('Invalid in the {0} test'.format(i))
        else:
            print('invalid in the ' + str(i + 1) + ' test')
    t2 = time.perf_counter() - t1
    print(f"用时:{t2} s")
    '''
