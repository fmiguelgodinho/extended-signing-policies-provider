package core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import com.etsy.net.UnixDomainSocket;

public class ACPSocketConnection {
	
	private String description;
	private InputStream is;
	private OutputStream os;
	
	
	public ACPSocketConnection(String description, UnixDomainSocket unixDomainSocket)
	throws IOException
	{
		this.description = description;
		is = unixDomainSocket.getInputStream();
		os = unixDomainSocket.getOutputStream();
	}
	
	public int receive(byte[] recv) 
	throws IOException 
	{		
		int readBytes = is.read(recv);
//		System.out.println(description + " received: " + new String(recv, "UTF-8"));
		return readBytes;
	}
	
	public void send(CallType t, byte[] payload)
	throws IOException
	{
		if (t == null)
			throw new IllegalArgumentException("Call cannot be null!");
		
		byte[] callNameBytes = t.getCallName().getBytes("UTF-8");
		
		ByteBuffer bb = payload != null ? 
			ByteBuffer.allocate(callNameBytes.length + payload.length + 1) :
			ByteBuffer.allocate(callNameBytes.length);
			
		bb.put(callNameBytes);
		
		int delimiterpos = -1; 
		
		if (payload != null) {
			delimiterpos = bb.position();
			bb.put((byte) 0x0a);
			bb.put(payload);
		}
		
		
		os.write(bb.array());
		os.flush();
		System.out.println(description + " sent: " + new String(delimiterpos > 0 ? 
				bb.put(delimiterpos, (byte) 0x0a).array() : bb.array(), "UTF-8"));
	}
	
	
	public void send(CallType t)
	throws IOException
	{
		this.send(t, null);
	}
}