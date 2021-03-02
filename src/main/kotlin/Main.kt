import java.io.*
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

fun encryptRSA(message: ByteArray, pubKey: PublicKey): ByteArray {
    val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, pubKey)
    return cipher.doFinal(message)
}

fun decryptRSA(message: ByteArray, privateKey: PrivateKey): ByteArray {
    val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    return cipher.doFinal(message)
}

fun sign(message: ByteArray, privateKey: PrivateKey): ByteArray {
    val privateSignature: Signature = Signature.getInstance("SHA256withRSA");
    privateSignature.initSign(privateKey);
    privateSignature.update(message);
    return privateSignature.sign()
}

fun verify(message: ByteArray, signature: ByteArray, pubKey: PublicKey): Boolean {
    val publicSignature: Signature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(pubKey)
    publicSignature.update(message)
    return publicSignature.verify(signature)
}

fun encrypt(message: ByteArray, pubKey: PublicKey): Pair<ByteArray, ByteArray> {
    val key = KeyGenerator.getInstance("AES").generateKey()
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    return Pair(cipher.doFinal(message), encryptRSA(key.encoded, pubKey))
}

fun decrypt(messageAndKey: Pair<ByteArray, ByteArray>, privateKey: PrivateKey): ByteArray {
    val decryptedKeySpec = decryptRSA(messageAndKey.second, privateKey)
    val key = SecretKeySpec(decryptedKeySpec, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key)
    return cipher.doFinal(messageAndKey.first)
}

fun serialize(obj: Serializable): ByteArray {
    val bos = ByteArrayOutputStream()
    val stream = ObjectOutputStream(bos)
    stream.writeObject(obj)
    stream.flush()
    return bos.toByteArray()
}

fun deserialize(data: ByteArray): Serializable {
    val bis = ByteArrayInputStream(data)
    val stream = ObjectInputStream(bis)
    return stream.readObject() as Serializable
}


class Step1(val pubKC: ByteArray) : Serializable
class Step2(val sid: Long, val signatureSID: ByteArray) : Serializable
class Step3(val pm: PM, val po: PO) : Serializable
class Step4(val pm: PM, val signature: ByteArray) : Serializable
class Step5(val resp: String, sid: Long, val signature: ByteArray) : Serializable
class Step6(val resp: String, val sid: Long, val signature: ByteArray) : Serializable

class PM(val pi: PI, val signature: ByteArray) : Serializable
class PO(val poData: POData, val signature: ByteArray) : Serializable
class POData(val orderDesc: String, val sid: Long, val amount: Double, val nc: Long) : Serializable
class PI(
    val cardN: String, val cardExp: Instant,
    val cCode: Long, val sid: Long, val amount: Double,
    val pubKC: ByteArray, val nc: Long, val m: Long
) : Serializable

class Step4SigData(val sid: Long, val pubKC: ByteArray, val amount: Double) : Serializable
class Step5SigData(val resp: String, val sid: Long, val amount: Double, val nc: Long) : Serializable

abstract class Participant {
    private val keyPair: KeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
    public val publicKey: PublicKey
        get() = this.keyPair.public
    protected val privateKey: PrivateKey
        get() = this.keyPair.private

    private fun sendMessage(msg: ByteArray, output: PipedOutputStream) {
        output.write(
            ByteBuffer.allocate(4)
                .putInt(msg.size).array()
        )
        output.write(msg)
    }

    private fun receiveMessage(input: PipedInputStream): ByteArray {
        val size = ByteBuffer.wrap((4 downTo 1).map { _ -> input.read().toByte() }.toByteArray()).int
        val buffer = LinkedList<Byte>()
        var data = input.read()
        while (data != -1 && buffer.size < size - 1) {
            buffer.add(data.toByte())
            data = input.read()
        }
        if (data == -1) return ByteArray(0)
        buffer.add(data.toByte())
        return buffer.toByteArray()
    }

    protected fun send(data: Serializable, pub: PublicKey, pipe: PipedOutputStream) {
        val packet = encrypt(serialize(data), pub)
        sendMessage(packet.first, pipe)
        sendMessage(packet.second, pipe)
    }

    protected fun receive(pipe: PipedInputStream): Serializable {
        val data = receiveMessage(pipe)
        val key = receiveMessage(pipe)
        val raw = decrypt(Pair(data, key), privateKey)
        return deserialize(raw)
    }
}

class Client(
    private val merchantPipes: Pair<PipedOutputStream, PipedInputStream>,
    private val merchantPublicKey: PublicKey
) : Participant(), Runnable {

    private var sid: Long? = null
    private fun sendStep1() {
        val step1 = Step1(publicKey.encoded)
        send(step1, merchantPublicKey, merchantPipes.first)
    }

    private fun awaitStep2(): Boolean {
        val step2 = receive(merchantPipes.second) as Step2
        sid = step2.sid
        val buffer = ByteBuffer.allocate(Long.SIZE_BYTES)
        buffer.putLong(step2.sid)
        return verify(buffer.array(), step2.signatureSID, merchantPublicKey)
    }

    private fun sendStep3() {
        val pi = PI("1234", Instant.now(), 1234, sid!!, 123.20, publicKey.encoded, 123, 456)
        val pm = PM(pi, sign(serialize(pi), privateKey))
        val poData = POData("asd", sid!!, pi.amount, pi.nc)
        val po = PO(poData, sign(serialize(poData), privateKey))
        val step3 = Step3(pm, po)
        send(step3, merchantPublicKey, merchantPipes.first)
    }

    override fun run() {
        // Sending Step1 to Merchant
        sendStep1()
        if (awaitStep2())
            println("Client: Merchant signature matches")
        else {
            println("Signature does not match")
            return
        }
        sendStep3()
        Thread.sleep(50000)
    }
}

class Merchant(
    private val clientPipes: Pair<PipedOutputStream, PipedInputStream>,
    private val pgPipes: Pair<PipedOutputStream, PipedInputStream>,
    var pgPublicKey: PublicKey?
) : Participant(), Runnable {

    private var sid: Long? = null
    private var pubKC: PublicKey? = null
    private var pm: PM? = null
    private var po: PO? = null
    private var resp: String? = null

    private fun awaitStep1() {
        println("Waiting for step 1 from client")
        val obj = receive(clientPipes.second) as Step1
        pubKC = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(obj.pubKC))
    }

    private fun sendStep2() {
        sid = Random().nextLong()
        val buffer = ByteBuffer.allocate(Long.SIZE_BYTES)
        buffer.putLong(sid!!)
        val signature = sign(buffer.array(), privateKey)
        val step2 = Step2(sid!!, signature)
        send(step2, pubKC!!, clientPipes.first)
    }

    private fun awaitStep3(): Boolean {
        val obj = receive(clientPipes.second) as Step3
        val verifyPI = verify(serialize(obj.pm.pi), obj.pm.signature, pubKC!!)
        val verifyPO = verify(serialize(obj.po.poData), obj.po.signature, pubKC!!)
        if (!(verifyPI && verifyPO && obj.pm.pi.sid == sid!! && obj.po.poData.sid == sid!!))
            return false
        pm = obj.pm
        po = obj.po
        return true
    }

    private fun sendStep4() {
        val sigData = Step4SigData(sid!!, pubKC!!.encoded, pm!!.pi.amount)
        val sig = sign(serialize(sigData), privateKey)
        val step4 = Step4(pm!!, sig)
        send(step4, pgPublicKey!!, pgPipes.first)
    }

    private fun awaitStep5(): Boolean {
        val obj = receive(pgPipes.second) as Step5
        resp = obj.resp
        val sigData = Step5SigData(resp!!, sid!!, pm!!.pi.amount, pm!!.pi.nc)
        return verify(serialize(sigData), obj.signature, pgPublicKey!!)
    }

    override fun run() {
        awaitStep1()
        sendStep2()
        if (!awaitStep3())
            return
        println("Merchant: Client signature matches")
        sendStep4()
        awaitStep5()
        if (!awaitStep5())
            return
        println("Merchant: PG signature matches")
        pgPipes.second.close()
        pgPipes.first.close()
    }
}

class PG(
    private val merchantPipes: Pair<PipedOutputStream, PipedInputStream>,
    private val merchantPublicKey: PublicKey
) : Participant(), Runnable {

    private var pm: PM? = null
    private val resp = "OK"

    private fun awaitStep4(): Boolean {
        val obj = receive(merchantPipes.second) as Step4
        val pmVerify = verify(
            serialize(obj.pm.pi), obj.pm.signature, KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(obj.pm.pi.pubKC))
        )
        val step4SigData = Step4SigData(obj.pm.pi.sid, obj.pm.pi.pubKC, obj.pm.pi.amount)
        val step4verify = verify(serialize(step4SigData), obj.signature, merchantPublicKey)
        pm = obj.pm
        return step4verify && pmVerify
    }

    private fun sendStep5() {
        val sigData = Step5SigData(resp, pm!!.pi.sid, pm!!.pi.amount, pm!!.pi.nc)
        val sig = sign(serialize(sigData), privateKey)
        val step5 = Step5(resp, pm!!.pi.sid, sig)
        send(step5, merchantPublicKey, merchantPipes.first)

    }

    override fun run() {
        if (!awaitStep4())
            return
        println("PG: Merchant and Client signatures match")
        sendStep5()
        merchantPipes.first.close()
        merchantPipes.second.close()
    }
}

fun createPipePair(): Pair<Pair<PipedOutputStream, PipedInputStream>, Pair<PipedOutputStream, PipedInputStream>> {
    val in1 = PipedInputStream()
    val in2 = PipedInputStream()
    val out1 = PipedOutputStream(in2)
    val out2 = PipedOutputStream(in1)
    return Pair(Pair(out1, in1), Pair(out2, in2))
}

fun main(args: Array<String>) {
    val clientMerchantPipes = createPipePair()
    val merchantPGPipes = createPipePair()
    val merchant = Merchant(clientMerchantPipes.first, merchantPGPipes.first, null)
    val client = Client(clientMerchantPipes.second, merchant.publicKey)
    val pg = PG(merchantPGPipes.second, merchant.publicKey)
    merchant.pgPublicKey = pg.publicKey

    val t1 = Thread(client)
    val t2 = Thread(merchant)
    val t3 = Thread(pg)
    t1.start()
    t2.start()
    t3.start()
}