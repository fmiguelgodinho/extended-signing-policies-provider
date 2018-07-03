package core;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonReader;

import com.etsy.net.JUDS;
import com.etsy.net.UnixDomainSocket;
import com.etsy.net.UnixDomainSocketClient;
import com.etsy.net.UnixDomainSocketServer;

import threshsig.Dealer;
import threshsig.GroupKey;
import threshsig.KeyShare;
import threshsig.SigShare;


/* XSP Module
* 
* Extended Signing Policies Provider for Peer processes within the HLF blockchain network
* 
* Supports:
* 	- Victor Shoup's Practical Threshold Signatures (https://github.com/sweis/threshsig)
* 
* 
*/
public class XSPServer {

	private String socketFileName;
	private int socketType;
	private int errors;

	public XSPServer(String pSocketFileName, int pSocketType) 
	throws IOException
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
	
	public int getErrors() {
		return errors;
	}
	
	public void runServer(UnixDomainSocketServer serverSocket)
	throws IOException, ClassNotFoundException
	{
		UnixDomainSocket socket = serverSocket.accept();  // we only need to accept once 	
		XSPSocketConnection conn = new XSPSocketConnection("Server -> Client:" + socketFileName, socket);
		
		byte[] recv;
		
		while (true) {
			
			recv = new byte[16000];
			conn.receive(recv);
			
			BufferedReader br = new BufferedReader(
				new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
			);
			
			String recvCall = br.readLine();		// get the call name
			String payload = br.readLine();			// get the payload
			
			if (recvCall == null || recvCall.isEmpty()) {
				logError(null, new Exception("Unexpected: Call was empty!"));
				continue;
			}
			
//			System.out.println("Received callName: " + recvCall + " payload: " + payload);
			
			JsonReader jread = Json.createReader(new StringReader(payload));
			JsonObject recvJson = jread.readObject();
			jread.close();
			
			CallType respCall = null;
			JsonObject respJson = null, cryptoInfo = null;
			String message = null;
			
			switch (CallType.parseCall(recvCall)) {
			
				case ThreshSigDealCall:
					int keySize = recvJson.getInt("key-size");
					int l = recvJson.getInt("l");
					int k = recvJson.getInt("k");
					
					// call deal fn and set return
					respCall = CallType.ThreshSigDealRet;
					respJson = genCryptoMaterial_ThreshSig(keySize, l, k);
					break;
					
				case ThreshSigSignCall:
					
					cryptoInfo = recvJson.getJsonObject("crypto");
					message = recvJson.getString("msg");
					JsonObject share = cryptoInfo.getJsonObject("share");
					
					int shid = share.getInt("id");
					BigInteger secret = share.getJsonNumber("secret").bigIntegerValue();
					BigInteger n = share.getJsonNumber("n").bigIntegerValue();
					BigInteger delta = share.getJsonNumber("delta").bigIntegerValue();
					BigInteger verifier = share.getJsonNumber("verifier").bigIntegerValue();
					BigInteger gverifier = share.getJsonNumber("group-verifier").bigIntegerValue();
					
					// call sign fn and set return
					respCall = CallType.ThreshSigSignRet;
					KeyShare sh = new KeyShare(shid, secret, n, delta, verifier, gverifier);
					respJson = sign_ThreshSig(sh, message.getBytes());
					break;
					
				case ThreshSigVerifyCall:
					
					cryptoInfo = recvJson.getJsonObject("crypto");
					message = recvJson.getString("msg");
					
					JsonObject groupKey = cryptoInfo.getJsonObject("group-key");
					
					// deserialize gk
					int vk = groupKey.getInt("k");
					int vl = groupKey.getInt("l");
					int vkeySize = groupKey.getInt("key-size");
					BigInteger vexp = groupKey.getJsonNumber("exp").bigIntegerValue();
					BigInteger vmod = groupKey.getJsonNumber("mod").bigIntegerValue();
					GroupKey gk = new GroupKey(vk, vl, vkeySize, null, vexp, vmod);
					
					// deserialize sig shares
					JsonArray arr = cryptoInfo.getJsonArray("signatures");
					SigShare[] sigs = new SigShare[arr.size()];
					
					for (int i = 0; i < arr.size(); i++) {
						
						JsonObject sigObj = arr.getJsonObject(i);
						int sigid = sigObj.getInt("id");
						byte[] sig64Bytes = sigObj.getString("signature").getBytes();
						byte[] sigBytes = Base64.getDecoder().decode(sig64Bytes);
						
						
						SigShare sig = new SigShare(sigid, sigBytes);
						sigs[i] = sig;
					}
					
					// call verify fn and set return
					respCall = CallType.ThreshSigVerifyRet;
					respJson = verify_ThreshSig(gk, sigs, message.getBytes());
					break;
					
				default:
					logError(null, new Exception("Unexpected: Unknown call!"));
					System.out.println("Unexpected: Unknown call!");
			}
			
			if (respCall == null) {
				logError(null, new Exception("Error: Wasn't able to find an appropriate response. Continuing..."));
				continue;
			}
			
			if (respJson == null) {
				conn.send(respCall);
			} else {
				conn.send(respCall, respJson.toString().getBytes("UTF-8"));
			}
				
		}
	}
	
	private JsonObject sign_ThreshSig(KeyShare ks, byte[] message) 
	throws IOException
	{
		
		// sign the message bytes
		SigShare sig = ks.sign(message);
		
		byte[] b64Sig = Base64.getEncoder().encode(sig.getBytes());
		
		return Json.createObjectBuilder()
				.add("id", sig.getId())
				.add("signature", new String(b64Sig, "UTF-8"))
				.build();
	}
	
	
	private JsonObject verify_ThreshSig(GroupKey gk, SigShare[] sigs, byte[] message) 
	throws IOException
	{
		boolean isValid = false;
		
		if (gk.getK() == sigs.length) {
			// verify message sig
			isValid = SigShare.verify(message, sigs, 
					gk.getK(), gk.getL(), gk.getModulus(), gk.getExponent());
		}
		
		return Json.createObjectBuilder()
				.add("valid", isValid)
				.build();
	}
	
	
	private JsonObject genCryptoMaterial_ThreshSig(int keySize, int l, int k) 
	throws UnsupportedEncodingException, IOException 
	{
		//TODO change to protobuf
		
		// Initialize a dealer with a keysize
		Dealer d = new Dealer(keySize);
		
		// Generate a set of key shares
		d.generateKeys(k, l);
		
		// Get public group key and private key shares: careful with the shares!
		GroupKey gk = d.getGroupKey();
		KeyShare[] keys = d.getShares();
		
		// open java serializer
		
		// create Json object from this info
		JsonArrayBuilder jabShares = Json.createArrayBuilder();
		for (KeyShare sh : keys) {

			// shares to json
			jabShares.add(Json.createObjectBuilder()
				.add("id", sh.getId())
				.add("secret", sh.getSecret())
				.add("n", sh.getN())
				.add("delta", sh.getDelta())
				.add("verifier", sh.getVerifier())
				.add("group-verifier", sh.getGroupVerifier())
			);
		}
		
		JsonObject cryptoInfo = Json.createObjectBuilder()
				.add("group-key", Json.createObjectBuilder()
						.add("k", gk.getK())
						.add("l", gk.getL())
						.add("key-size", keySize)
						.add("exp", gk.getExponent())
						.add("mod", gk.getModulus()))
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
		UnixDomainSocketClient clientSocket = new UnixDomainSocketClient("/tmp/hlf-xsp.sock", JUDS.SOCK_STREAM);
		XSPSocketConnection conn = new XSPSocketConnection("Client -> Server:" + socketFileName, clientSocket);		
		
		// emulate deal call
		byte[] recv = new byte[16000];
		BufferedReader br = new BufferedReader(
				new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
		);
		
		conn.send(CallType.ThreshSigDealCall, Json.createObjectBuilder()
				.add("l", 6)
				.add("k", 5)
				.add("key-size", 512)
				.build()
				.toString().getBytes("UTF-8"));
		
		System.out.println("1. Requested for generation of group key and shares: (l,k,keySize) = (" 
				+ 6 + "," + 5 + "," + 512 + ")");
		
		conn.receive(recv);
		String recvCall = br.readLine();		// get the call name
		String payload = br.readLine();			// get the payload
	

		JsonReader jread = Json.createReader(new StringReader(payload));
		JsonObject recvJson = jread.readObject();
		jread.close();
		
		JsonObject pubkey = recvJson.getJsonObject("group-key");
		

		System.out.println("2. Successfully got group key and shares.");
		
//		Thread.sleep(2000);

		int[] sharepos = {0, 1, 2, 3, 5};
		JsonObject[] sigshares = new JsonObject[5];
		for (int i = 0; i < 5; i++) {
			
			JsonObject shobj = recvJson.getJsonArray("shares").get(sharepos[i]).asJsonObject();
			
			int myid = shobj.getInt("id");
			

			System.out.println("3. (" + (i+1) + "/5) Requesting signing of message m with share id = " + myid);
		
			conn.send(CallType.ThreshSigSignCall, Json.createObjectBuilder()
					.add("crypto", Json.createObjectBuilder().add("share", shobj))
					.add("msg", "lorem ipsum dolor sit amet, " +
								"consectetur adipiscing elit, " + 
							 	"sed do eiusmod tempor incididunt " + 
								"ut labore et dolore magna aliqua.")
					.build()
					.toString().getBytes("UTF-8"));

			recv = new byte[16000];
			br = new BufferedReader(
					new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
			);

			conn.receive(recv);
			recvCall = br.readLine();		// get the call name
			payload = br.readLine();			// get the payload
			

			jread = Json.createReader(new StringReader(payload));
			JsonObject recvJson2 = jread.readObject();
			jread.close();
			
			sigshares[i] = recvJson2;
//			Thread.sleep(1000);
		}
		

		System.out.println("4. Collected 5 signature shares.");
		System.out.println("5. Requesting verification of legitimate message m...");
		
		conn.send(CallType.ThreshSigVerifyCall, Json.createObjectBuilder()
				.add("crypto", Json.createObjectBuilder()
						.add("group-key", pubkey)
						.add("signatures", Json.createArrayBuilder()
								.add(sigshares[0])
								.add(sigshares[1])
								.add(sigshares[2])
								.add(sigshares[3])
								.add(sigshares[4])))
				.add("msg", "lorem ipsum dolor sit amet, " +
							"consectetur adipiscing elit, " + 
						 	"sed do eiusmod tempor incididunt " + 
							"ut labore et dolore magna aliqua.")
				.build()
				.toString().getBytes("UTF-8"));

		recv = new byte[1000];
		br = new BufferedReader(
				new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
		);

		conn.receive(recv);
		recvCall = br.readLine();		// get the call name
		payload = br.readLine();			// get the payload
		
		System.out.println("6. Result of verification = " + payload);
		
		System.out.println("7. Requesting verification of tampered message m...");
		
		conn.send(CallType.ThreshSigVerifyCall, Json.createObjectBuilder()
				.add("crypto", Json.createObjectBuilder()
						.add("group-key", pubkey)
						.add("signatures", Json.createArrayBuilder()
								.add(sigshares[0])
								.add(sigshares[1])
								.add(sigshares[2])
								.add(sigshares[3])
								.add(sigshares[4])))
				.add("msg", "lorem ipsum dolor sit amet, " +
						"consectetur VIRUS elit, " + 
					 	"sed do eiusmod tempor incididunt " + 
						"ut ATTACK et dolore magna aliqua.")
				.build()
				.toString().getBytes("UTF-8"));
		
		recv = new byte[1000];
		br = new BufferedReader(
				new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
		);

		conn.receive(recv);
		recvCall = br.readLine();		// get the call name
		payload = br.readLine();			// get the payload
		
		System.out.println("8. Result of verification = " + payload);
		
		System.out.println("9. Requesting verification of legitimate message m with a missing signature share...");
		
		conn.send(CallType.ThreshSigVerifyCall, Json.createObjectBuilder()
				.add("crypto", Json.createObjectBuilder()
						.add("group-key", pubkey)
						.add("signatures", Json.createArrayBuilder()
								.add(sigshares[0])
								.add(sigshares[1])
								// missing sig share #2
								.add(sigshares[3])
								.add(sigshares[4])))
				.add("msg", "lorem ipsum dolor sit amet, " +
						"consectetur adipiscing elit, " + 
					 	"sed do eiusmod tempor incididunt " + 
						"ut labore et dolore magna aliqua.")
				.build()
				.toString().getBytes("UTF-8"));
		
		recv = new byte[1000];
		br = new BufferedReader(
				new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
		);

		conn.receive(recv);
		recvCall = br.readLine();		// get the call name
		payload = br.readLine();			// get the payload
		
		System.out.println("10. Result of verification = " + payload);
		
		System.out.println("11. Requesting verification of legitimate message m with forged signature share...");
		
		
		// TODO CHANGE THIS TO BE OK
		sigshares[3] = Json.createObjectBuilder()
				.add("id", sigshares[3].getInt("id"))
				.add("signature", "FTFbeDgNM5pIBljUzLilrNWYLr7JMtxhUTAWJWEdqpDrQlF4viFcpzaZlxC18bwUiQBYm4tLyY53NQi79afDSrdzYS4bGLU77HUWFXKM3VgXne0IKz9zFCluqGvPPrqZy+Ck09ZOZLKqSjg7QoIea8Z3tVSZIU8ofJfVSEGN8NQ=")
				.build();
		

		
		conn.send(CallType.ThreshSigVerifyCall, Json.createObjectBuilder()
				.add("crypto", Json.createObjectBuilder()
						.add("group-key", pubkey)
						.add("signatures", Json.createArrayBuilder()
								.add(sigshares[0])
								.add(sigshares[1])
								.add(sigshares[2])
								.add(sigshares[3])
								.add(sigshares[4])))
				.add("msg", "lorem ipsum dolor sit amet, " +
						"consectetur adipiscing elit, " + 
					 	"sed do eiusmod tempor incididunt " + 
						"ut labore et dolore magna aliqua.")
				.build()
				.toString().getBytes("UTF-8"));
		
		recv = new byte[1000];
		br = new BufferedReader(
				new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8")
		);

		conn.receive(recv);
		recvCall = br.readLine();		// get the call name
		payload = br.readLine();			// get the payload
		
		System.out.println("12. Result of verification = " + payload);
		System.out.println("E2E test done.");
	}
	
	public void start() throws IOException, InterruptedException {
		
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
					catch (IOException e)
					{
						logError(new Object[]{"Server socket failure"},e);
					} catch (ClassNotFoundException e) {
						logError(new Object[]{"Server deserialization failure"},e);
					}
				}
			};
			serverThread.start();
		}
		finally
		{
//			if (server !=null)
//			{
//				server.unlink();
//			}
		}
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
					catch (IOException e)
					{
						logError(new Object[]{"Server socket failure"},e);
					} catch (ClassNotFoundException e) {
						logError(new Object[]{"Server deserialization failure"},e);
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
	
//			serverThread.join();
		}
		finally
		{
//			if (server !=null)
//			{
//				server.unlink();
//			}
		}
	}

}
