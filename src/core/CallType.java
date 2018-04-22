package core;

public enum CallType {
	
	ThreshSigDealCall("__CALL_THRESH_SIG_DEAL"),		// call to gen l shares and group pubkey
	ThreshSigDealRet("__RET_THRESH_SIG_DEAL"),
	ThreshSigSignCall("__CALL_THRESH_SIG_SIGN"),		// call to sign using input share
	ThreshSigSignRet("__RET_THRESH_SIG_SIGN"),
	NoOp("__NO_CALL");
	
	
	private String callName;
	
	CallType(String callName) {
		this.callName = callName;
	}
	
	String getCallName() {
		return callName;
	}
	
	static CallType parseCall(String callName) {
		
		switch (callName) {
			case "__CALL_THRESH_SIG_DEAL":
				return ThreshSigDealCall;
			case "__CALL_THRESH_SIG_SIGN":
				return ThreshSigSignCall;
		}
		
		return NoOp;
	}
}
