import java.io.IOException;

import com.etsy.net.JUDS;

import core.XSPServer;

public class Main {

		
	public static void main(String[] args)
	{
		if (args.length != 1) {
			System.out
					.println("usage: java Main <socket-file-path>");
			System.exit(1);
		}
		
		try {
			XSPServer srv = new XSPServer(args[0], JUDS.SOCK_STREAM);
			
			try {
//				srv.start();
				srv.fullTest();
			}
			catch (Exception exception)
			{
				srv.logError(null, exception);
			}
				
			if (srv !=null)
			{
				if (srv.getErrors() == 0)
				{
					System.out.println("Started XSP service on socket " + args[0] + "...");
				}
			}	
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
