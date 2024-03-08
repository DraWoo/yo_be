package com.yo.sm.core.exception;

import java.util.Map;

public class BizException extends RuntimeException {

	private Map<String, Object> extra;

	private String errorCode;

	public BizException() {
		super();
	}

	public BizException(String msg) {
		super(msg);
	}

	public BizException(Exception e) {
		super(e);
	}

	public BizException(String msg, String errorCode) {
		super(msg);
		this.errorCode = errorCode;
	}

	public BizException(String msg, String errorCode , Map<String, Object> extra) {
		super(msg);
		this.extra = extra;
		this.errorCode = errorCode;
	}

	public Map<String, Object> getExtra() {
		return extra;
	}

	public String getErrorCode() {
		return errorCode;
	}
}
