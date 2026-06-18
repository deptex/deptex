# Reachable dependency CVE: parses a user-supplied XML document with REXML.
# params[:xml] flows straight into REXML::Document.new, the vulnerable parser
# entry point for CVE-2021-28965 (rexml 3.2.4 XML parse-amplification DoS).
# Mirrors the proven ruby-vulns shape: bare params[:x] -> local var -> sink,
# then return a constant.
require "rexml/document"

class DocumentsController < ApplicationController
  def parse
    # REACHABLE: redos (CVE-2021-28965) — untrusted XML into REXML parser
    xml = params[:xml]
    REXML::Document.new(xml)
    head :ok
  end
end
