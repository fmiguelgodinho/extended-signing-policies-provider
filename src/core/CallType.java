package core;

public enum CallType {
	
	ThreshSigDealCall("__CALL_THRESHSIG_DEAL"),		// call to gen l shares and group pubkey
	ThreshSigDealRet("__RETU_THRESHSIG_DEAL"),
	ThreshSigSignCall("__CALL_THRESHSIG_SIGN"),		// call to sign using input share
	ThreshSigSignRet("__RETU_THRESHSIG_SIGN"),
	ThreshSigVerifyCall("__CALL_THRESHSIG_VERI"),		// call to sign using input share
	ThreshSigVerifyRet("__RETU_THRESHSIG_VERI"),
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
			case "__CALL_THRESHSIG_DEAL":
				return ThreshSigDealCall;
			case "__CALL_THRESHSIG_SIGN":
				return ThreshSigSignCall;
			case "__CALL_THRESHSIG_VERI":
				return ThreshSigVerifyCall;
		}
		
		return NoOp;
	}
}
