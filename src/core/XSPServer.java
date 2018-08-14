package core;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

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
import threshsig.ThresholdSigException;

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

	public static int THREAD_POOL_SIZE = 8;

	private static String socketFileName;
	private static int socketType;
	private static int errors;

	public XSPServer(String pSocketFileName, int pSocketType) throws IOException {
		socketFileName = pSocketFileName;
		socketType = pSocketType;
		errors = 0;
		String threadszEnvVar = System.getenv("XSP_THREAD_POOL_SIZE");
		if (threadszEnvVar != null && !threadszEnvVar.isEmpty()) {
			THREAD_POOL_SIZE = Integer.parseInt(threadszEnvVar);
		}
	}

	public UnixDomainSocketServer initServer() throws IOException {
		return new UnixDomainSocketServer(socketFileName, socketType, 3);
	}

	public int getErrors() {
		return errors;
	}

	private static class XSPAttendTask implements Runnable {

		UnixDomainSocketServer serverSocket;
		String threadName;

		public XSPAttendTask(UnixDomainSocketServer serverSocket, String threadName) {
			this.serverSocket = serverSocket;
			this.threadName = threadName;
		}

		@Override
		public void run() {

			int ncalls = 0;
			while (true) {

				try {
					UnixDomainSocket socket = null;
					synchronized (this) {
						socket = serverSocket.accept(); // we only need to accept once
					}
					XSPSocketConnection conn = new XSPSocketConnection("Server -> Client:" + socketFileName, socket);

					byte[] recv = new byte[4096];
					int recvNr = conn.receive(recv);

					if (recvNr < 0)
						break;

					BufferedReader br = new BufferedReader(
							new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8"));

					String recvCall = br.readLine(); // get the call name
					String payload = br.readLine(); // get the payload

					if (recvCall == null || recvCall.isEmpty() || CallType.parseCall(recvCall) == CallType.NoOp) {
						logError(null, new Exception("Unexpected: Call was empty!"));
						continue;
					}

					ncalls++;
					System.out.println(this.threadName + ": Received call #" + ncalls + " callName: " + recvCall
							+ " payload: " + payload);

					JsonReader jread = Json.createReader(new StringReader(payload));
					JsonObject recvJson = jread.readObject();
					jread.close();

					CallType respCall = null;
					JsonObject respJson = null;
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

						String share = recvJson.getString("share");
						message = recvJson.getString("msg");

						// call sign fn and set return
						respCall = CallType.ThreshSigSignRet;
						respJson = sign_ThreshSig(share.getBytes("UTF-8"), message.getBytes("UTF-8"));
						break;

					case ThreshSigVerifyCall:

						String groupKey = recvJson.getString("group-key");
						message = recvJson.getString("msg");

						// deserialize sig shares
						JsonArray arr = recvJson.getJsonArray("signatures");
						byte[][] sigs = new byte[arr.size()][];
						for (int i = 0; i < arr.size(); i++) {
							sigs[i] = arr.getString(i).getBytes("UTF-8");
						}

						// call verify fn and set return
						respCall = CallType.ThreshSigVerifyRet;
						respJson = verify_ThreshSig(groupKey.getBytes("UTF-8"), sigs, message.getBytes("UTF-8"));
						break;

					default:
						logError(null, new Exception("Unexpected: Unknown call!"));
						System.out.println("Unexpected: Unknown call!");
					}

					if (respCall == null) {
						logError(null,
								new Exception("Error: Wasn't able to find an appropriate response. Continuing..."));
						continue;
					}

					if (respJson == null) {
						conn.send(respCall);
					} else {
						conn.send(respCall, respJson.toString().getBytes("UTF-8"));
					}

					System.out.println("Returned call #" + ncalls);
					br.close();
					socket.close();

				} catch (Exception e) {
					logError(null, new Exception("Unexpected: Thread exploded during attend task!"));
				}
			}
		}
	}

	public void runServer(UnixDomainSocketServer serverSocket) throws IOException, ClassNotFoundException {

		for (int i = 0; i < THREAD_POOL_SIZE; i++) {
			new Thread(new XSPAttendTask(serverSocket, "thread-xspp-" + i)).start();
		}
	}

	private static JsonObject sign_ThreshSig(byte[] ks, byte[] message) throws IOException {
		// retrieve key share
		KeyShare sh = KeyShare.fromBytes(ks);

		// sign the message bytes
		SigShare sig = sh.sign(message);

		return Json.createObjectBuilder().add("id", sig.getId()).add("signature", sig.toString()).build();
	}

	private static JsonObject verify_ThreshSig(byte[] key, byte[][] sigs, byte[] message) throws IOException {
		boolean isValid = false;

		// parse group key
		GroupKey gk = GroupKey.fromBytes(key);

		// convert the 64b strings to sig shares
		SigShare[] ssh = new SigShare[sigs.length];
		for (int i = 0; i < sigs.length; i++) {
			ssh[i] = SigShare.fromBytes(sigs[i]);
		}

		if (gk.getK() <= sigs.length) {
			// verify message sig

			try {
				isValid = SigShare.verifyCombinations(message, ssh, gk);
				// isValid = SigShare.verify(message, ssh,
				// gk.getK(), gk.getL(), gk.getModulus(), gk.getExponent());
			} catch (ThresholdSigException tse) {
				// continue, isValid == false, signature was either null, duplicate or tampered
			}
		}

		return Json.createObjectBuilder().add("valid", isValid).build();
	}

	private static JsonObject genCryptoMaterial_ThreshSig(int keySize, int l, int k)
			throws UnsupportedEncodingException, IOException {

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
			jabShares.add(Json.createObjectBuilder().add("id", sh.getId()).add("share", sh.toString()));
		}

		JsonObject cryptoInfo = Json.createObjectBuilder().add("group-key", gk.toString()).add("shares", jabShares)
				.build();

		return cryptoInfo;
	}

	public static void logError(Object[] pInfos, Throwable pThrowable) {
		errors++;
		if (pThrowable != null) {
			pThrowable.printStackTrace(System.err);
		}
		System.out.println(pInfos);
	}

	public void runClient() throws IOException, InterruptedException {
		UnixDomainSocketClient clientSocket = new UnixDomainSocketClient("/tmp/hlf-xsp.sock", JUDS.SOCK_STREAM);
		XSPSocketConnection conn = new XSPSocketConnection("Client -> Server:" + socketFileName, clientSocket);

		// emulate deal call
		byte[] recv = new byte[16000];
		BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8"));

		conn.send(CallType.ThreshSigDealCall, Json.createObjectBuilder().add("l", 6).add("k", 5).add("key-size", 512)
				.build().toString().getBytes("UTF-8"));

		System.out.println("1. Requested for generation of group key and shares: (l,k,keySize) = (" + 6 + "," + 5 + ","
				+ 512 + ")");

		conn.receive(recv);
		
		
		@SuppressWarnings("unused")
		String recvCall = br.readLine(); // get the call name
		String payload = br.readLine(); // get the payload

		JsonReader jread = Json.createReader(new StringReader(payload));
		JsonObject recvJson = jread.readObject();
		jread.close();

		String pubkey = recvJson.getString("group-key");

		System.out.println("2. Successfully got group key and shares:" + recvJson);

		clientSocket.close();
		clientSocket = new UnixDomainSocketClient("/tmp/hlf-xsp.sock", JUDS.SOCK_STREAM);
		conn = new XSPSocketConnection("Client -> Server:" + socketFileName, clientSocket);

		// Thread.sleep(2000);

		int[] sharepos = { 0, 1, 2, 3, 4, 5 };
		String[] sigshares = new String[6];
		for (int i = 0; i < 6; i++) {

			JsonObject shobj = recvJson.getJsonArray("shares").get(sharepos[i]).asJsonObject();

			int myid = shobj.getInt("id");

			System.out.println("3. (" + (i + 1) + "/6) Requesting signing of message m with share id = " + myid);

			conn.send(CallType.ThreshSigSignCall,
					Json.createObjectBuilder().add("share", shobj.getString("share"))
							.add("msg",
									"lorem ipsum dolor sit amet, " + "consectetur adipiscing elit, "
											+ "sed do eiusmod tempor incididunt " + "ut labore et dolore magna aliqua.")
							.build().toString().getBytes("UTF-8"));

			recv = new byte[16000];
			br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8"));

			conn.receive(recv);
			recvCall = br.readLine(); // get the call name
			payload = br.readLine(); // get the payload

			jread = Json.createReader(new StringReader(payload));
			JsonObject recvJson2 = jread.readObject();
			jread.close();

			sigshares[i] = recvJson2.getString("signature");
			// Thread.sleep(1000);

			clientSocket.close();
			clientSocket = new UnixDomainSocketClient("/tmp/hlf-xsp.sock", JUDS.SOCK_STREAM);
			conn = new XSPSocketConnection("Client -> Server:" + socketFileName, clientSocket);
		}

		System.out.println("4. Collected 6 signature shares.");
		System.out.println("5. Requesting verification of legitimate message m...");

		conn.send(CallType.ThreshSigVerifyCall,
				Json.createObjectBuilder().add("group-key", pubkey)
						.add("signatures",
								Json.createArrayBuilder().add(sigshares[0]).add(sigshares[1]).add(sigshares[2])
										.add(sigshares[3]).add(sigshares[4]).add(sigshares[5]))
						.add("msg",
								"lorem ipsum dolor sit amet, " + "consectetur adipiscing elit, "
										+ "sed do eiusmod tempor incididunt " + "ut labore et dolore magna aliqua.")
						.build().toString().getBytes("UTF-8"));

		recv = new byte[1000];
		br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8"));

		conn.receive(recv);
		recvCall = br.readLine(); // get the call name
		payload = br.readLine(); // get the payload

		System.out.println("6. Result of verification = " + payload);

		clientSocket.close();
		clientSocket = new UnixDomainSocketClient("/tmp/hlf-xsp.sock", JUDS.SOCK_STREAM);
		conn = new XSPSocketConnection("Client -> Server:" + socketFileName, clientSocket);

		System.out.println("7. Requesting verification of tampered message m...");

		conn.send(CallType.ThreshSigVerifyCall,
				Json.createObjectBuilder().add("group-key", pubkey)
						.add("signatures",
								Json.createArrayBuilder().add(sigshares[0]).add(sigshares[1]).add(sigshares[2])
										.add(sigshares[3]).add(sigshares[4]))
						.add("msg",
								"lorem ipsum dolor sit amet, " + "consectetur VIRUS elit, "
										+ "sed do eiusmod tempor incididunt " + "ut ATTACK et dolore magna aliqua.")
						.build().toString().getBytes("UTF-8"));

		recv = new byte[1000];
		br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8"));

		conn.receive(recv);
		recvCall = br.readLine(); // get the call name
		payload = br.readLine(); // get the payload

		System.out.println("8. Result of verification = " + payload);

		System.out.println("9. Requesting verification of legitimate message m with a missing signature share...");
		

		clientSocket.close();
		clientSocket = new UnixDomainSocketClient("/tmp/hlf-xsp.sock", JUDS.SOCK_STREAM);
		conn = new XSPSocketConnection("Client -> Server:" + socketFileName, clientSocket);

		conn.send(CallType.ThreshSigVerifyCall,
				Json.createObjectBuilder().add("group-key", pubkey)
						.add("signatures", Json.createArrayBuilder().add(sigshares[0]).add(sigshares[1])
								// missing sig share #2
								.add(sigshares[3]).add(sigshares[4]))
						.add("msg",
								"lorem ipsum dolor sit amet, " + "consectetur adipiscing elit, "
										+ "sed do eiusmod tempor incididunt " + "ut labore et dolore magna aliqua.")
						.build().toString().getBytes("UTF-8"));

		recv = new byte[1000];
		br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8"));

		conn.receive(recv);
		recvCall = br.readLine(); // get the call name
		payload = br.readLine(); // get the payload

		System.out.println("10. Result of verification = " + payload);

		System.out.println("11. Requesting verification of legitimate message m with forged signature share...");

		clientSocket.close();
		clientSocket = new UnixDomainSocketClient("/tmp/hlf-xsp.sock", JUDS.SOCK_STREAM);
		conn = new XSPSocketConnection("Client -> Server:" + socketFileName, clientSocket);

		// TODO CHANGE THIS TO BE OK
		sigshares[3] = "FTFbeDgNM5pIBljUzLilrNWYLr7JMtxhUTAWJWEdqpDrQlF4viFcpzaZlxC18bwUiQBYm4tLyY53NQi79afDSrdzYS4bGLU77HUWFXKM3VgXne0IKz9zFCluqGvPPrqZy+Ck09ZOZLKqSjg7QoIea8Z3tVSZIU8ofJfVSEGN8NQ=";

		conn.send(CallType.ThreshSigVerifyCall,
				Json.createObjectBuilder().add("group-key", pubkey)
						.add("signatures",
								Json.createArrayBuilder().add(sigshares[0]).add(sigshares[1]).add(sigshares[2])
										.add(sigshares[3]).add(sigshares[4]))
						.add("msg",
								"lorem ipsum dolor sit amet, " + "consectetur adipiscing elit, "
										+ "sed do eiusmod tempor incididunt " + "ut labore et dolore magna aliqua.")
						.build().toString().getBytes("UTF-8"));

		recv = new byte[1000];
		br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(recv), "UTF-8"));

		conn.receive(recv);
		recvCall = br.readLine(); // get the call name
		payload = br.readLine(); // get the payload

		System.out.println("12. Result of verification = " + payload);
		System.out.println("E2E test done.");

		clientSocket.close();
	}

	public void start() throws IOException, InterruptedException {

		// do it now to avoid any race condition between socket creation and client
		// first start
		final UnixDomainSocketServer server = initServer();

		try {
			Thread serverThread = new Thread() {
				public void run() {
					try {
						runServer(server);
					} catch (IOException e) {
						logError(new Object[] { "Server socket failure" }, e);
					} catch (ClassNotFoundException e) {
						logError(new Object[] { "Server deserialization failure" }, e);
					}
				}
			};
			serverThread.start();
		} finally {
			// if (server !=null)
			// {
			// server.unlink();
			// }
		}
	}

	public void fullTest() throws InterruptedException, IOException {

		// do it now to avoid any race condition between socket creation and client
		// first start
		final UnixDomainSocketServer server = initServer();

		try {
			Thread serverThread = new Thread() {
				public void run() {
					try {
						runServer(server);
					} catch (IOException e) {
						logError(new Object[] { "Server socket failure" }, e);
					} catch (ClassNotFoundException e) {
						logError(new Object[] { "Server deserialization failure" }, e);
					}
				}
			};

			serverThread.start();

			for (int i = 0; i < 100; i++) {
				Thread clientThread = new Thread() {
					public void run() {
						try {
							runClient();
						} catch (IOException ioException) {
							logError(new Object[] { "Client socket failure" }, ioException);
						} catch (InterruptedException e) {
							e.printStackTrace();
						}
					}
				};

				clientThread.start();
			}
			// clientThread.join();

			// serverThread.join();
		} finally {
			// if (server !=null)
			// {
			// server.unlink();
			// }
		}
	}

}
