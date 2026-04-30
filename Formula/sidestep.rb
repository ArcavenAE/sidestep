# Homebrew formula for sidestep (stable channel)
# Updated automatically by CI on tagged releases (v*)
# macOS only (arm64). Linux support is a future option.

class Sidestep < Formula
  desc "Rust CLI for the StepSecurity API — codegen from OpenAPI, audit-trail-as-feature"
  homepage "https://github.com/ArcavenAE/sidestep"
  version "VERSION_PLACEHOLDER"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/ArcavenAE/sidestep/releases/download/TAG_PLACEHOLDER/sidestep-darwin-arm64"
    sha256 "SHA256_DARWIN_ARM64_PLACEHOLDER"
  else
    odie "sidestep currently only supports macOS arm64. Build from source for other platforms."
  end

  def install
    bin.install "sidestep-darwin-arm64" => "sidestep"
  end

  def caveats
    <<~EOS
      sidestep needs a StepSecurity API token before it can call the API.
      Recommended (keychain bootstrap):

        sidestep auth login --token <bearer-token>

      Verify:

        sidestep auth status

      Discover and invoke operations:

        sidestep ops list
        sidestep api <operationId> --param key=value

      Every API call writes a structured JSONL audit line under
      ~/.sidestep/audit/ (macOS) or ~/.local/state/sidestep/audit/ (Linux).
    EOS
  end

  test do
    assert_match "sidestep", shell_output("#{bin}/sidestep --version 2>&1")
  end
end
