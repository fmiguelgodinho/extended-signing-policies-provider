import java.io.IOException;

import com.etsy.net.JUDS;

import core.ACPModule;

public class Main {

		
	public static void main(String[] args)
	{
		if (args.length != 1) {
			System.out
					.println("usage: java ACPModule <socket-file-path>");
			System.exit(1);
		}
		
		try {
			ACPModule mod = new ACPModule(args[0], JUDS.SOCK_STREAM);
			
			try {
				mod.fullTest();
			}
			catch (Exception exception)
			{
				mod.logError(null, exception);
			}
				
			if (mod !=null)
			{
				if (mod.getErrors() == 0)
				{
					System.out.println("Started ACPModule service on socket " + args[0] + "...");
				}
			}	
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
