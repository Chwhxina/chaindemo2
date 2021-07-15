package com.wuhan.chaindemo;

import com.alipay.mychain.sdk.api.MychainClient;
import com.alipay.mychain.sdk.api.callback.IEventCallback;
import com.alipay.mychain.sdk.api.env.ClientEnv;
import com.alipay.mychain.sdk.api.env.ISslOption;
import com.alipay.mychain.sdk.api.env.SignerOption;
import com.alipay.mychain.sdk.api.env.SslBytesOption;
import com.alipay.mychain.sdk.api.logging.AbstractLoggerFactory;
import com.alipay.mychain.sdk.api.logging.ILogger;
import com.alipay.mychain.sdk.api.utils.Utils;
import com.alipay.mychain.sdk.common.VMTypeEnum;
import com.alipay.mychain.sdk.crypto.MyCrypto;
import com.alipay.mychain.sdk.crypto.keyoperator.Pkcs8KeyOperator;
import com.alipay.mychain.sdk.crypto.keypair.Keypair;
import com.alipay.mychain.sdk.crypto.signer.SignerBase;
import com.alipay.mychain.sdk.domain.account.Identity;
import com.alipay.mychain.sdk.domain.event.EventModelType;
import com.alipay.mychain.sdk.errorcode.ErrorCode;
import com.alipay.mychain.sdk.message.Message;
import com.alipay.mychain.sdk.message.event.PushAccountEvent;
import com.alipay.mychain.sdk.message.event.PushContractEvent;
import com.alipay.mychain.sdk.message.event.PushTopicsEvent;
import com.alipay.mychain.sdk.message.transaction.AbstractTransactionRequest;
import com.alipay.mychain.sdk.type.BaseFixedSizeUnsignedInteger;
import com.alipay.mychain.sdk.utils.ByteUtils;
import com.alipay.mychain.sdk.utils.IOUtil;
import com.alipay.mychain.sdk.utils.RandomUtil;
import com.alipay.mychain.sdk.vm.EVMOutput;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Chris
 * @date 2021/5/29 20:45
 * @Email:gang.wu@nexgaming.com
 */
public class JREventDemo {
    private static String contractCodeString = "6080604052633b9aca00600055600060015534801561001d57600080fd5b50336002819055506104e8806100346000396000f300608060405260043610610062576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806357fce39d14610067578063af7c102c14610092578063b2628df8146100d3578063d448601914610122575b600080fd5b34801561007357600080fd5b5061007c610171565b6040518082815260200191505060405180910390f35b34801561009e57600080fd5b506100bd6004803603810190808035906020019092919050505061017b565b6040518082815260200191505060405180910390f35b3480156100df57600080fd5b506101086004803603810190808035906020019092919080359060200190929190505050610198565b604051808215151515815260200191505060405180910390f35b34801561012e57600080fd5b50610157600480360381019080803590602001909291908035906020019092919050505061035d565b604051808215151515815260200191505060405180910390f35b6000600254905090565b600060036000838152602001908152602001600020549050919050565b600060025433141515610213576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260118152602001807f5065726d697373696f6e2064656e69656400000000000000000000000000000081525060200191505060405180910390fd5b60005482600154011315801561022e57506001548260015401135b801561023a5750600082135b15156102ae576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f496e76616c69642076616c75652100000000000000000000000000000000000081525060200191505060405180910390fd5b8160036000858152602001908152602001600020600082825401925050819055508160016000828254019250508190555081837f9a46fdc9277c739031110f773b36080a9a2012d0b3eca1f5ed8a3403973e05576001546040518080602001838152602001828103825260048152602001807f64656d6f000000000000000000000000000000000000000000000000000000008152506020019250505060405180910390a36001905092915050565b6000816003600033815260200190815260200160002054121515156103ea576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260138152602001807f62616c616e6365206e6f7420656e6f756768210000000000000000000000000081525060200191505060405180910390fd5b6000821380156103fc57506000548213155b1515610470576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f496e76616c69642076616c75652100000000000000000000000000000000000081525060200191505060405180910390fd5b81600360003381526020019081526020016000206000828254039250508190555081600360008581526020019081526020016000206000828254019250508190555060019050929150505600a165627a7a72305820fadd6bb10cae5a1cb7c61bfd06a8e0c6a6930816e55c7cbcec4d7edf882608380029";
    private static byte[] contractCode = ByteUtils.hexStringToBytes(contractCodeString); //CreditManager

    //upgrade
    private static String contractUpdateCodeString = "60806040526004361061006d576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680631b3c4fab1461007257806357fce39d14610187578063af7c102c146101b2578063b2628df8146101f3578063d448601914610242575b600080fd5b34801561007e57600080fd5b50610087610291565b60405180868152602001806020018060200185151515158152602001848152602001838103835287818151815260200191508051906020019080838360005b838110156100e15780820151818401526020810190506100c6565b50505050905090810190601f16801561010e5780820380516001836020036101000a031916815260200191505b50838103825286818151815260200191508051906020019080838360005b8381101561014757808201518184015260208101905061012c565b50505050905090810190601f1680156101745780820380516001836020036101000a031916815260200191505b5097505050505050505060405180910390f35b34801561019357600080fd5b5061019c61035e565b6040518082815260200191505060405180910390f35b3480156101be57600080fd5b506101dd60048036038101908080359060200190929190505050610368565b6040518082815260200191505060405180910390f35b3480156101ff57600080fd5b506102286004803603810190808035906020019092919080359060200190929190505050610385565b604051808215151515815260200191505060405180910390f35b34801561024e57600080fd5b50610277600480360381019080803590602001909291908035906020019092919050505061054a565b604051808215151515815260200191505060405180910390f35b6000606080600080606080600080600033905060649250600191506040805190810160405280600381526020017f61626300000000000000000000000000000000000000000000000000000000008152509450606060405190810160405280602481526020017f303132333435363738396162636465666768696a6b6c6d6e6f7071727374757681526020017f7778797a00000000000000000000000000000000000000000000000000000000815250935082858584849950995099509950995050505050509091929394565b6000600254905090565b600060036000838152602001908152602001600020549050919050565b600060025433141515610400576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260118152602001807f5065726d697373696f6e2064656e69656400000000000000000000000000000081525060200191505060405180910390fd5b60005482600154011315801561041b57506001548260015401135b80156104275750600082135b151561049b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f496e76616c69642076616c75652100000000000000000000000000000000000081525060200191505060405180910390fd5b8160036000858152602001908152602001600020600082825401925050819055508160016000828254019250508190555081837f9a46fdc9277c739031110f773b36080a9a2012d0b3eca1f5ed8a3403973e05576001546040518080602001838152602001828103825260048152602001807f64656d6f000000000000000000000000000000000000000000000000000000008152506020019250505060405180910390a36001905092915050565b6000816003600033815260200190815260200160002054121515156105d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260138152602001807f62616c616e6365206e6f7420656e6f756768210000000000000000000000000081525060200191505060405180910390fd5b6000821380156105e957506000548213155b151561065d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f496e76616c69642076616c75652100000000000000000000000000000000000081525060200191505060405180910390fd5b81600360003381526020019081526020016000206000828254039250508190555081600360008581526020019081526020016000206000828254019250508190555060019050929150505600a165627a7a7230582055e7ed92be846fa5e7275a674a052647504bddcf5971e064251639503be328ac0029";
    private static byte[] contractUpdateCode = ByteUtils.hexStringToBytes(contractUpdateCodeString); //CreditManager



    /**
     * contract id
     */
    private static String callContractId = "jmtc1622284493081";

    private static final String account = "chrisblocktest";
    private static Identity userIdentity;
    private static Keypair userKeypair;

    /**
     * sdk client
     */
    private static MychainClient sdk;

    /**
     * client key password
     */
    private static String keyPassword = "Local#123";
    /**
     * user password
     */
    private static String userPassword = "Local#123";
    /**
     * host ip
     */

    private static String host = "47.103.163.48";

    /**
     * server port
     */
    private static int port = 18130;
    /**
     * trustCa password.
     */
    private static String trustStorePassword = "mychain";
    /**
     * mychain environment
     */
    private static ClientEnv env;
    /**
     * mychain is tee Chain
     */
    private static boolean isTeeChain = false;
    /**
     * tee chain publicKeys
     */
    private static List<byte[]> publicKeys = new ArrayList<byte[]>();
    /**
     * tee chain secretKey
     */
    private static String secretKey = "123456";


    private static void initMychainEnv() throws IOException {
        // any user key for sign message
        String userPrivateKeyFile = "user.key";
        userIdentity = Utils.getIdentityByName(account);
        Pkcs8KeyOperator pkcs8KeyOperator = new Pkcs8KeyOperator();
        userKeypair = pkcs8KeyOperator.load(IOUtil.inputStreamToByte(JREventDemo.class.getClassLoader().getResourceAsStream(userPrivateKeyFile)), userPassword);

        // use publicKeys by tee
        if (isTeeChain) {
            Keypair keypair = new Pkcs8KeyOperator()
                    .loadPubkey(
                            IOUtil.inputStreamToByte(JREventDemo.class.getClassLoader().getResourceAsStream("test_seal_pubkey.pem")));
            byte[] publicKeyDer = keypair.getPubkeyEncoded();
            publicKeys.add(publicKeyDer);
        }

        env = buildMychainEnv();
        ILogger logger = AbstractLoggerFactory.getInstance(JREventDemo.class);
        env.setLogger(logger);
    }

    private static ClientEnv buildMychainEnv() throws IOException {
        InetSocketAddress inetSocketAddress = InetSocketAddress.createUnresolved(host, port);
        String keyFilePath = "client.key";
        String certFilePath = "client.crt";
        String trustStoreFilePath = "trustCa";
        // build ssl option
        ISslOption sslOption = new SslBytesOption.Builder()
                .keyBytes(IOUtil.inputStreamToByte(JREventDemo.class.getClassLoader().getResourceAsStream(keyFilePath)))
                .certBytes(IOUtil.inputStreamToByte(JREventDemo.class.getClassLoader().getResourceAsStream(certFilePath)))
                .keyPassword(keyPassword)
                .trustStorePassword(trustStorePassword)
                .trustStoreBytes(
                        IOUtil.inputStreamToByte(JREventDemo.class.getClassLoader().getResourceAsStream(trustStoreFilePath)))
                .build();

        List<InetSocketAddress> socketAddressArrayList = new ArrayList<InetSocketAddress>();
        socketAddressArrayList.add(inetSocketAddress);

        List<SignerBase> signerBaseList = new ArrayList<SignerBase>();
        SignerBase signerBase = MyCrypto.getInstance().createSigner(userKeypair);
        signerBaseList.add(signerBase);
        SignerOption signerOption = new SignerOption();
        signerOption.setSigners(signerBaseList);
        return ClientEnv.build(socketAddressArrayList, sslOption, signerOption);
    }

    private static void initSdk() {
        sdk = new MychainClient();
        boolean initResult = sdk.init(env);
        if (!initResult) {
            exit("initSdk", "sdk init failed.");
        }else{
            System.out.println("sdk init success");
        }
    }

    private static String getErrorMsg(int errorCode) {
        int minMychainSdkErrorCode = ErrorCode.SDK_INTERNAL_ERROR.getErrorCode();
        if (errorCode < minMychainSdkErrorCode) {
            return ErrorCode.valueOf(errorCode).getErrorDesc();
        } else {
            return ErrorCode.valueOf(errorCode).getErrorDesc();
        }
    }

    private static void exit(String tag, String msg) {
        exit(String.format("%s error : %s ", tag, msg));
    }

    private static void exit(String msg) {
        System.out.println(msg);
        System.exit(0);
    }

    private static void signRequest(AbstractTransactionRequest request) {
        // sign request
        long ts = sdk.getNetwork().getSystemTimestamp();
        request.setTxTimeNonce(ts, BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger
                .valueOf(RandomUtil.randomize(ts + request.getTransaction().hashCode())), true);
        request.complete();
        sdk.getConfidentialService().signRequest(env.getSignerOption().getSigners(), request);
    }

    //订阅账户
    private static void listenAccountTest(){
        // event handler
        IEventCallback handler = new IEventCallback() {
            @Override
            public void onEvent(Message message) {
                PushAccountEvent accountEvent = (PushAccountEvent) message;
                //code
            }
        };

        BigInteger eventId = sdk.getEventService().listenAccount(userIdentity, handler, EventModelType.PUSH);
        if (eventId.longValue() == 0) {
            System.out.println("listenAccount failed");
        }
    }

    //订阅合约
    private static void listenContractTest(){
        //event handler
        IEventCallback handler = new IEventCallback() {
            @Override
            public void onEvent(Message message) {
                PushContractEvent eventContractMessage = (PushContractEvent) message;
                // code
            }
        };

        BigInteger eventId = sdk.getEventService().listenContract(userIdentity, handler, EventModelType.PUSH);
        if (eventId.longValue() == 0) {
            System.out.println("listenContract failed");
        }
    }

    private static BigInteger listenTopicsTest(){
        // event handler
        IEventCallback handler = new IEventCallback() {
            @Override
            public void onEvent(Message message) {
                PushTopicsEvent eventTopicsMessage = (PushTopicsEvent) message;
                //code
                if(eventTopicsMessage.getResults().size() > 0){
                    String topic = eventTopicsMessage.getResults().get(0).getTopic();
                    byte[] logData = eventTopicsMessage.getResults().get(0).getData();
                    if(logData != null && logData.length > 0){
                        EVMOutput eventLogValues = new EVMOutput(ByteUtils.toHexString(logData));
                        String str1 = eventLogValues.getString();
                        BigInteger issueAmount = eventLogValues.getUint();
                        System.out.println(String.format("Topic is %s, Event Log Data：string1 is %s,total issueAmount is %d",topic,str1,issueAmount));
                    } else {
                        System.out.println(String.format("Topic is %s",topic));
                    }
                }
            }
        };
        List<String> topics = new ArrayList<String>();
        //topics.add("call_contract");

        /* 这种方式得不到指定的topic事件回调
        IHash hashTool = HashFactory.getHash();
        byte[] sha256 = hashTool.hash("IssueEvent(identity,int256,string,int256)".getBytes());
        topics.add(ByteUtils.toHexString(sha256));
        */

        //这种方式就可以得到，查看sdk源码，底层使用传入的字符串做了Keccak Hash,接口层不用单独做hash
        topics.add("JrChrisIssueEvent(identity,int256,string,int256)");

        // listen topics
        BigInteger eventId = sdk.getEventService().listenTopics(topics, handler, VMTypeEnum.EVM, EventModelType.PUSH);
        return eventId;
    }

    public static void main(String[] args) throws Exception {
        //step 1:init mychain env.
        initMychainEnv();
        //step 2: init sdk client
        initSdk();

        BigInteger eventId = listenTopicsTest();
        if (eventId.longValue() == 0) {
            System.out.println("listenTopics failed");
            return ;
        }

        System.in.read();

        if(eventId.longValue() != 0){
            sdk.getEventService().unListenTopics(eventId);
        }

        sdk.shutDown();
    }

}
