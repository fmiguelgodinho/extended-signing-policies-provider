package core;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import com.etsy.net.JUDS;
import com.etsy.net.UnixDomainSocket;
import com.etsy.net.UnixDomainSocketClient;
import com.etsy.net.UnixDomainSocketServer;

import threshsig.Dealer;
import threshsig.GroupKey;
import threshsig.KeyShare;
import threshsig.SigShare;

import javax.json.*;


/* ACP Module
* 
* Advanced Cryptographic Provider for Peer/Orderer processes within the HLF blockchain network
* 
* Supports:
* 	- Victor Shoup's Practical Threshold Signatures (https://github.com/sweis/threshsig)
* 
* 
*/
public class ACPModule {

	private String socketFileName;
	private int socketType;
	private int errors;
	
	public ACPModule(String pSocketFileName, int pSocketType)
	{
		socketFileName = pSocketFileName;
		socketType = pSocketType;
		errors=0;
	}
	
	public UnixDomainSocketServer initServer()
	throws IOException
	{
		 return new UnixDomainSocketServer(socketFileName, socketType, 3);
	}
	
	public void runServer(UnixDomainSocketServer serverSocket)
	throws IOException
	{
		UnixDomainSocket socket = serverSocket.accept();  // we only need to accept once 	
		ACPSocketConnection conn = new ACPSocketConnection("Server -> Client:" + socketFileName, socket);
		
		byte[] recv;
		
		while (true) {
			
			recv = new byte[4096];
			conn.receive(recv);
			
			BufferedReader br = new BufferedReader(
				new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
			);
			
			String recvCall = br.readLine();		// get the call name
			String payload = br.readLine();			// get the payload
			
			if (recvCall == null || recvCall.isEmpty()) {
				System.out.println("Unexpected: Call was empty!");
				continue;
			}
			
			System.out.println("Received callName: " + recvCall + " payload: " + payload);
			
			JsonReader jread = Json.createReader(new StringReader(payload));
			JsonObject recvJson = jread.readObject();
			jread.close();
			
			CallType respCall = null;
			JsonObject respJson = null;
			
			switch (CallType.parseCall(recvCall)) {
			
				case ThreshSigDealCall:
					int keySize = recvJson.getInt("key-size");
					int l = recvJson.getInt("l");
					int k = recvJson.getInt("k");
					
					respCall = CallType.ThreshSigDealRet;
					respJson = generateThreshSigInfo(keySize, l, k);
					break;
					
				case ThreshSigSignCall:
					
					JsonObject cryptoInfo = recvJson.getJsonObject("crypto");
					JsonObject message = recvJson.getJsonObject("msg");
					
					int id = cryptoInfo.getInt("id");
					BigInteger secret = new BigInteger(cryptoInfo.getString("secret"));
					BigInteger verifier = new BigInteger(cryptoInfo.getString("verifier"));
					BigInteger groupKeyMod = new BigInteger(cryptoInfo.getString("group-key-mod"));
					BigInteger delta = new BigInteger(cryptoInfo.getString("delta"));
					
					respCall = CallType.ThreshSigSignRet;
					respJson = signPayload(id, secret, verifier, groupKeyMod, delta, message.toString().getBytes());
					break;
					
				default:
					System.out.println("Unexpected: Unknown call!");
			}
			
			if (respCall == null) {
				System.out.println("Error: Wasn't able to find an appropriate response. Continuing...");
				continue;
			}
			
			if (respJson == null) {
				conn.send(respCall);
			} else {
				conn.send(respCall, respJson.toString().getBytes("UTF-8"));
			}
				
		}
	}
	
	private JsonObject signPayload(int id, BigInteger secret, BigInteger n, BigInteger verifier, BigInteger delta, byte[] message)
	{
		KeyShare rebuiltShare = new KeyShare(id, secret, n, delta);
		
		SigShare sig = rebuiltShare.sign(message);
		byte[] sigBytes = sig.getBytes();
		
		return Json.createObjectBuilder()
				.add("signature", new String(sigBytes))
				.build();
	}
	
	
	private JsonObject generateThreshSigInfo(int keySize, int l, int k) 
	throws UnsupportedEncodingException, IOException 
	{
		//TODO change to protobuf
		
		// Initialize a dealer with a keysize
		Dealer d = new Dealer(keySize);
		
		// Generate a set of key shares
		d.generateKeys(l, k);
		
		// Get public group key and private key shares: careful with the shares!
		GroupKey gk = d.getGroupKey();
		KeyShare[] keys = d.getShares();
		
		// create Json object from this info
		JsonArrayBuilder jabShares = Json.createArrayBuilder();
		for (KeyShare sh : keys) {
			jabShares.add(Json.createObjectBuilder()
					.add("id", sh.getId())
					.add("secret", sh.getSecret())
					.add("verifier", sh.getVerifier())
					// shares will need two additional params to reconstruct:
					// n - get the modulus of the group key
					// l - get the exponent of l from the group key
			);
		}
		
		JsonObject cryptoInfo = Json.createObjectBuilder()
				.add("group-key", Json.createObjectBuilder()
					.add("mod", gk.getModulus())
					.add("exp", gk.getExponent())
					.add("k", gk.getK())
					.add("l", gk.getL())
				)
				.add("shares", jabShares)
				.build();
		
		return cryptoInfo;
	}
	
	
	public void logError( Object[] pInfos, Throwable pThrowable)
	{
		errors++;
		if (pThrowable != null)
		{
			pThrowable.printStackTrace(System.err);
		}
		System.out.println(pInfos);
	}
	
	public void runClient()
	throws IOException, InterruptedException
	{
		UnixDomainSocketClient clientSocket = new UnixDomainSocketClient(socketFileName, socketType);
		ACPSocketConnection connection = new ACPSocketConnection("Client -> Server:" + socketFileName, clientSocket);		
		
		// emulate deal call
		
		connection.send(CallType.ThreshSigDealCall, Json.createObjectBuilder()
				.add("l", 8)
				.add("k", 6)
				.add("key-size", 512)
				.build()
				.toString().getBytes("UTF-8"));
		
		Thread.sleep(1000);
		
		connection.send(CallType.ThreshSigSignCall, Json.createObjectBuilder()
				.add("crypto", Json.createObjectBuilder()
						.add("id", 1)
						.add("secret", "10727420309829906525352996079833348708267470306578275297502475763563182530358570770147720116050131771957471383523157655614262286494901587606732156075487972172610516027174295393382006776182766946820720579036912363173618801259441055230087331758077951357917356551824955614546863298958849312781746579120736753362063619421802714371789863195946859304160")
						.add("verifier", "28097948391887958392526830312920760289826519950299350809244282238332182175819438274024756914775046373766580671723685494926792450035766691998221036021989391761895355988431703311946111374339741703313561492736652518476442130149596294526528745261673227934483323620670139252123714528876288532162087285639867342570")
						.add("group-key-mod", "55646919153154303327633441910368951325134328009878805854939551252824659381385343746707649069079367112309924280775782341304039902321190383987415435795445687493109555975894397847596229272487758277189190212627005306170430773080131405543976392657930186574317802023936351701212622467511322228817548988643887096443")
						.add("delta", "40320"))
				.add("msg", Json.createObjectBuilder()
						.add("tx_id", 2182381)
						.add("transaction_from", "bill")
						.add("transaction_to", "mandy")
						.add("value", 123131.329329)
						.add("ccid", "eccc"))
				.build()
				.toString().getBytes("UTF-8"));
	}
	
	
	public void fullTest()
	throws InterruptedException, IOException
	{
		
		// do it now to avoid any race condition between socket creation and client first start
		final UnixDomainSocketServer server = initServer();
		
		try {
			Thread serverThread = new Thread()
			{
				public void run()
				{
					try {
						runServer(server);
					}
					catch (IOException ioException)
					{
						logError(new Object[]{"Server socket failure"},ioException);
					}
				}
			};
			
			serverThread.start();
			Thread clientThread = new Thread()
			{
				public void run()
				{
					try {
						runClient();
					}
					catch (IOException ioException)
					{
						logError(new Object[]{"Client socket failure"}, ioException);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			};
			
			clientThread.start();
			clientThread.join();
	
			serverThread.join();
		}
		finally
		{
			if (server !=null)
			{
				server.unlink();
			}
		}
	}
		
	public static void main(String[] args)
	{
		if (args.length != 1) {
			System.out
					.println("usage: java ACPModule <socket-file-path>");
			System.exit(1);
		}
		ACPModule thisTest = new ACPModule(args[0], JUDS.SOCK_STREAM);
		
		try {
			thisTest.fullTest();
		}
		catch (Exception exception)
		{
			thisTest.logError(null, exception);
		}
			
		if (thisTest !=null)
		{
			if (thisTest.errors == 0)
			{
				System.out.println("Started ACPModule service on socket " + args[0] + "...");
			}
		}	
	}

}
