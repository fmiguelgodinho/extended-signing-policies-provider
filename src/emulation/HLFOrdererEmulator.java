package emulation;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.etsy.net.*;


/**
 * Standalone java Test code for new API with listen/accept
 * Can be used as example.
 * 
 * Test is just to exchange string hello handshake between a server and a client through a unix domain socket with file given in argument.
 * 
 * @author plhardy
 *
 */
public class HLFOrdererEmulator 
{

	private String socketFileName;
	private int socketType;
	private int errors;
	
	private class SocketConnection {
		private String description;
		private InputStream is;
		private OutputStream os;
		public SocketConnection(String pDescription, UnixDomainSocket pUnixDomainSocket)
		throws IOException
		{
			description = pDescription;
			is = pUnixDomainSocket.getInputStream();
			os = pUnixDomainSocket.getOutputStream();
		}
		
		public void expect(String pSentence)
		throws IOException
		{
			byte[] expected = new byte[pSentence.getBytes("UTF8").length];
			int read = is.read(expected);
			if (read == expected.length)
			{
				if (new String(expected, "UTF8").equals(pSentence))
				{
					System.out.println("" + description + " received :" + pSentence);
					return;
				}
			}
			throw new IOException("Unexpected");
		}
		
		public void send(String pSentence)
		throws IOException
		{
			os.write(pSentence.getBytes("UTF8"));
			System.out.println("" + description + " sent :" + pSentence);
		}
	}
	
	public HLFOrdererEmulator(String pSocketFileName, int pSocketType)
	{
		socketFileName = pSocketFileName;
		socketType = pSocketType;
		errors=0;
	}
	
	
	public void logError( Object[] pInfos, Throwable pThrowable)
	{
		errors ++;
		if (pThrowable != null)
		{
			pThrowable.printStackTrace(System.err);
		}
		System.out.println(pInfos);
	}

	public void runClient()
	throws IOException
	{
		System.out.println(socketFileName + ","+ socketType);
		UnixDomainSocketClient clientSocket = new UnixDomainSocketClient(socketFileName, JUDS.SOCK_STREAM);
		SocketConnection connection = new SocketConnection("Client -> Server on " + socketFileName, clientSocket);		
		connection.send("Init");
		//connection.expect("Server Hello");
	}
	
	public void fullTest()
	throws InterruptedException, IOException
	{
		
		try {

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
					}
				}
			};
			
			clientThread.start();
		}
		finally
		{
			
		}
		
		
	}
		
	public static void main(String[] args)
	{
		if (args.length != 1) {
			System.out
					.println("usage: java HLFOrdererEmulator socketfilename");
			System.exit(1);
		}
		HLFOrdererEmulator thisTest = new HLFOrdererEmulator(args[0], JUDS.SOCK_STREAM);
		
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
				System.out.println("Orderer emulatord pointing at socket " + args[0]);
			}
		}	
	}
}
