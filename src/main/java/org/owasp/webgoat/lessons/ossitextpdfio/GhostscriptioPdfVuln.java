package org.owasp.webgoat.lessons.ossitextpdfio;

import java.io.IOException;

import com.itextpdf.io.util.GhostscriptHelper;

public class GhostscriptioPdfVuln {

	String runGhostScriptImageGeneration(String pdf, String outDir, String image) {
	
		GhostscriptHelper gs=new GhostscriptHelper();
		try {
			gs.runGhostScriptImageGeneration(pdf, outDir, image);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return "success";
	}
	
}
