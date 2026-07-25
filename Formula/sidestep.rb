# Homebrew formula template for the sidestep STABLE channel.
# Updated ONLY by .github/workflows/release.yml on exact-semver v* tags —
# never by branch pushes. Alpha (sidestep-a, from develop) and release
# candidates (sidestep-rc, from merges to main) live in sibling formulas
# so `brew upgrade sidestep` moves tag-to-tag and nothing else.
# macOS only (arm64). Linux support is a future option.

class Sidestep < Formula
  # Homebrew desc audit: <= 80 chars (incl. any channel suffix), capitalized,
  # no leading article, must not start with the formula name, no trailing period.
  desc "Rust CLI for the StepSecurity API — OpenAPI codegen, audit trail built in"
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
      Stable channel: moves only on tagged releases. For the bleeding
      edge install `sidestep-a` (develop) or `sidestep-rc` (release
      candidates); all three coexist.

      Bootstrap a token (recommended — uses macOS Keychain):

        sidestep auth login --token <bearer-token>
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
