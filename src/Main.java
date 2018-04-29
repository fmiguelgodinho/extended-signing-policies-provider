import java.io.IOException;

import com.etsy.net.JUDS;

import core.ACPServer;

public class Main {

		
	public static void main(String[] args)
	{
		if (args.length != 1) {
			System.out
					.println("usage: java ACPModule <socket-file-path>");
			System.exit(1);
		}
		
		try {
			ACPServer srv = new ACPServer(args[0], JUDS.SOCK_STREAM);
			
			try {
//				srv.fullTest();
				srv.start();
			}
			catch (Exception exception)
			{
				srv.logError(null, exception);
			}
				
			if (srv !=null)
			{
				if (srv.getErrors() == 0)
				{
					System.out.println("Started ACP service on socket " + args[0] + "...");
				}
			}	
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
