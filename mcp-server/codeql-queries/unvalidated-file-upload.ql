/**
 * @name Unvalidated file upload without size or type checks
 * @description Detects file upload handlers that read uploaded file content
 *              without validating file size, content type, or file extension.
 *              A malicious upload could exhaust memory (DoS) or write unexpected
 *              file types to the server.
 * @kind problem
 * @problem.severity warning
 * @id icc-mcp/unvalidated-file-upload
 * @tags security file-upload dos input-validation
 */

import python

/**
 * Calls that read uploaded file content: request.form(), file.read(),
 * await upload.read(), UploadFile.read()
 */
class FileReadCall extends Call {
  FileReadCall() {
    this.getFunc().(Attribute).getName() in ["read", "form"] and
    exists(Function f |
      f.getName() in [
        "api_upload", "api_output_download",
        "handle_upload", "upload_profile"
      ] and
      this.getScope() = f
    )
  }
}

/**
 * Size validation checks on uploaded files.
 */
class SizeValidation extends Compare {
  SizeValidation() {
    exists(Call c |
      (
        c.getFunc().(Name).getId() = "len" or
        c.getFunc().(Attribute).getName() in ["content_length", "size"]
      ) and
      this.getASubExpression() = c
    )
  }
}

/**
 * Content type validation.
 */
class ContentTypeCheck extends Compare {
  ContentTypeCheck() {
    exists(Attribute a |
      a.getName() in ["content_type", "filename"] and
      this.getASubExpression() = a
    )
  }
}

from FileReadCall readCall, Function handler
where
  handler = readCall.getScope() and
  not exists(SizeValidation sv | sv.getScope() = handler) and
  not exists(ContentTypeCheck ctc | ctc.getScope() = handler)
select readCall,
  "File upload in " + handler.getName() +
  " reads content without size limit or content type validation. " +
  "Add MAX_UPLOAD_SIZE check and validate file extension/MIME type."
