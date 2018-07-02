package core;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;

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
			ObjectInputStream in = null;
			
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
					String encShare = cryptoInfo.getString("share");
					
					byte[] serializedShare = Base64.getDecoder().decode(encShare.getBytes());
					
					// deserialize share
					in = new ObjectInputStream(new ByteArrayInputStream(serializedShare));
					KeyShare sh = (KeyShare) in.readObject();
					
					// call sign fn and set return
					respCall = CallType.ThreshSigSignRet;
					respJson = sign_ThreshSig(sh, message.getBytes());
					break;
					
				case ThreshSigVerifyCall:
					
					cryptoInfo = recvJson.getJsonObject("crypto");
					message = recvJson.getString("msg");
					
					String encGroupKey = cryptoInfo.getString("group-key");
					byte[] serializedGroupKey = Base64.getDecoder().decode(encGroupKey.getBytes());
					
					// deserialize gk
					in = new ObjectInputStream(new ByteArrayInputStream(serializedGroupKey));
					GroupKey gk = (GroupKey) in.readObject();
					
					// deserialize sig shares
					JsonArray arr = cryptoInfo.getJsonArray("signatures");
					SigShare[] sigs = new SigShare[arr.size()];
					
					for (int i = 0; i < arr.size(); i++) {
						
						String encSig = ((JsonString) arr.get(i)).getString();
						byte[] serializedSig = Base64.getDecoder().decode(encSig.getBytes());
						in = new ObjectInputStream(new ByteArrayInputStream(serializedSig));
						SigShare sig = (SigShare) in.readObject();
						
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
	
	private JsonObject sign_ThreshSig(KeyShare sh, byte[] message) 
	throws IOException
	{
		// sign the message bytes
		SigShare sig = sh.sign(message);
		
		// open java serializer
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(buf);
		out.writeObject(sig);
		
		// encode to b64 and put into json
		byte[] sigBytes = Base64.getEncoder().encode(buf.toByteArray());
		
		out.close();
		
		return Json.createObjectBuilder()
				.add("signature", new String(sigBytes))
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

			// serialize shares
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(buf);
			out.writeObject(sh);
			out.close();
			
			byte[] shBytes = Base64.getEncoder().encode(buf.toByteArray());
			
			jabShares.add(Json.createObjectBuilder()
				.add("id", sh.getId())
				.add("share", new String(shBytes))
			);
		}
		

		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(buf);
		out.writeObject(gk);

		byte[] gkBytes = Base64.getEncoder().encode(buf.toByteArray());
		
		JsonObject cryptoInfo = Json.createObjectBuilder()
				.add("group-key", new String(gkBytes))
				.add("shares", jabShares)
				.build();
		
		out.close();
		
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
				.add("l", 8)
				.add("k", 5)
				.add("key-size", 512)
				.build()
				.toString().getBytes("UTF-8"));
		
		System.out.println("1. Requested for generation of group key and shares: (l,k,keySize) = (" 
				+ 8 + "," + 5 + "," + 512);
		
		conn.receive(recv);
		String recvCall = br.readLine();		// get the call name
		String payload = br.readLine();			// get the payload
		

		JsonReader jread = Json.createReader(new StringReader(payload));
		JsonObject recvJson = jread.readObject();
		jread.close();
		
		String pubkey = recvJson.getString("group-key");
		

		System.out.println("2. Successfully got group key and shares.");
		
//		Thread.sleep(2000);

		int[] sharepos = {0, 2, 3, 5, 7};
		String[] sigshares = new String[5];
		for (int i = 0; i < 5; i++) {
			
			JsonObject shobj = recvJson.getJsonArray("shares").get(sharepos[i]).asJsonObject();
			
			int myid = shobj.getInt("id");
			String mysh = shobj.getString("share");
			

			System.out.println("3. (" + (i+1) + "/5) Requesting signing of message m with share id = " + myid);
		
			conn.send(CallType.ThreshSigSignCall, Json.createObjectBuilder()
					.add("crypto", Json.createObjectBuilder()
							.add("id", myid)
							.add("share", mysh))
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
			
			sigshares[i] = recvJson2.getString("signature");
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
		
		sigshares[3] = "rO0ABXNyABJ0aHJlc2hzaWcuU2lnU2hhcmU9glIxI4V1bAIAA0kAAmlkTAADc2lndAAWTGphdmEvbWF0aC9CaWdJbnRlZ2VyO0wAC3NpZ1ZlcmlmaWVydAAUTHRocmVzaHNpZy9WZXJpZmllcjt4cAAAAAZzcgAUamF2YS5tYXRoLkJpZ0ludGVnZXKM/J8fqTv7HQMABkkACGJpdENvdW50SQAJYml0TGVuZ3RoSQATZmlyc3ROb256ZXJvQnl0ZU51bUkADGxvd2VzdFNldEJpdEkABnNpZ251bVsACW1hZ25pdHVkZXQAAltCeHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhw///////////////+/////gAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAAAgEQlMQfZaEOMCYjMfPa48zYD6LYqT+lHYNvAeiP9WNLN8U2l8X1JdSywklJhrNX6hn2MPe91hj6TFgYdrns4UkNJn4p/nr1pNaO0GjSXEH44Ka/nA0Y8RP543fdd2Bu1OJflVVZq0/dQkHd3VHzyzJxGFVwPaScs/FmLdKvkTfXreHNyABJ0aHJlc2hzaWcuVmVyaWZpZXKXROU5Q9BVhQIABEwAAWNxAH4AAUwADWdyb3VwVmVyaWZpZXJxAH4AAUwADXNoYXJlVmVyaWZpZXJxAH4AAUwAAXpxAH4AAXhwc3EAfgAE///////////////+/////gAAAAF1cQB+AAgAAACAV2wONb3dB/L04PANigxJmG57xxmS3QolPPcQQJUmpvGzys6HD9i309pLQyyBbejxekU9mJcTn1soQZ8sdixELFoo0nRndGo6XiiKb7uPC1BCH+qskce+wdsUfFbSH9CvXrbip/JGVclSA9DH3Vi4oi3pJoJJ9gXaoTP6yjJcg4h4c3EAfgAE///////////////+/////gAAAAF1cQB+AAgAAACAQ6PAEZfuEbSqVXD5Uu5eYkikgVyeZiciCggIVVnElhSEuLfF7eNXRQgsH7FmgJomjmzyQH6ud/PDsr/fMOeiUTm6T+s97PCQl/hXprJEy5kzRHa8jBQl+YMAmxWlg1vt7Brj9LLvp0loh0cwj4TTFR6Ui0+HbBaiuc83FrMc53F4c3EAfgAE///////////////+/////gAAAAF1cQB+AAgAAACAG7ErO+ATPDFn4JxJ284yfEVlw0FzEcbvFzmrJWlsWcygT6kqOXu2lrf3/nyvm9vJNO9wClwiBxBzSjyMVZUyeSCmk2dV5RYwMDP33HmCkL5PCZLtdnJMVP2JU8V/fSB+qUUkhrnwRIu5nAMP4MNx0Lo1HlQGpmWVJsCAkGdYigN4c3EAfgAE///////////////+/////gAAAAF1cQB+AAgAAAEQEh+zMAlelabxGdY1D/mDw28KYHJxPFxo1+vNJt6Z55AlXzD1mVW6YNoTSfAgxHaYYSzJ/YSlB7Pz3leW5ONxj+nI84jtNKtqiUcEHP44seQGCzIsAz69JVEEuSzj1iLG9Y41XDgtfCknV//qwIckaybFimKffEydm7IrNq04/rI+goK8Fw8ZYCOWrRxOtX352DLOgwwsCl1AyZHDcveW1ppUQkriVXz6r3bvbjHDv0geuda4MvHiu4u/5TvTr2xD+zF546tqxSRU2yT39xYUK3vr+e2PX/HvU71ZpuS2KxnEO+3uZuEqH+tITkRHoYdBRtY4DzGc5r0OmId55vT+vGnHsinoH6x92Xp6yXVU+154";
		
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
			if (server !=null)
			{
				server.unlink();
			}
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
