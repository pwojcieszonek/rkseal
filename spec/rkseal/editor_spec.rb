# frozen_string_literal: true

RSpec.describe RKSeal::Editor do
  # A throwaway file standing in for the SecureWorkspace-provided RAM path.
  # Editor only writes/reads it; it never creates or deletes it, so the spec
  # owns its lifecycle. No real secret ever lives here.
  let(:buffer_path) { File.join(Dir.mktmpdir, "buffer") }

  # Build a tiny executable shell script that acts as a fake "$EDITOR". The
  # body receives the buffer path as its last argument, so a script can inspect
  # or rewrite the buffer just like a real editor would.
  def fake_editor_script(body)
    fake_editor_named("fake-editor", body)
  end

  # Same fake editor, but with a chosen executable name so the side-file
  # hardening (which keys off the command's basename) can be exercised.
  def fake_editor_named(name, body)
    path = File.join(Dir.mktmpdir, name)
    File.write(path, "#!/bin/sh\n#{body}\n")
    File.chmod(0o755, path)
    path
  end

  describe "#resolve_command" do
    it "prefers an injected command over the environment" do
      editor = described_class.new(command: "injected-editor")

      with_env("VISUAL" => "visual-editor", "EDITOR" => "editor-editor") do
        expect(editor.resolve_command).to eq("injected-editor")
      end
    end

    it "prefers $VISUAL over $EDITOR when no command is injected" do
      editor = described_class.new

      with_env("VISUAL" => "vim", "EDITOR" => "nano") do
        expect(editor.resolve_command).to eq("vim")
      end
    end

    it "falls back to $EDITOR when $VISUAL is unset" do
      editor = described_class.new

      with_env("VISUAL" => nil, "EDITOR" => "nano") do
        expect(editor.resolve_command).to eq("nano")
      end
    end

    it "skips a blank $VISUAL and uses $EDITOR" do
      editor = described_class.new

      with_env("VISUAL" => "   ", "EDITOR" => "nano") do
        expect(editor.resolve_command).to eq("nano")
      end
    end

    it "raises EditorError when neither is set" do
      editor = described_class.new

      with_env("VISUAL" => nil, "EDITOR" => nil) do
        expect { editor.resolve_command }
          .to raise_error(RKSeal::EditorError, /VISUAL or \$EDITOR/)
      end
    end
  end

  describe "#edit", :allow_exec do
    it "seeds the path with content, launches the editor, and returns the edited result" do
      editor_path = fake_editor_script('printf "edited-by-user" > "$1"')
      editor = described_class.new(command: editor_path)

      result = editor.edit(content: "seed-content", path: buffer_path)

      expect(result).to eq("edited-by-user")
    end

    it "writes the seed content to the path before the editor runs" do
      # The fake editor copies whatever it was handed into a side file, proving
      # the seed reached disk before launch.
      seen = File.join(Dir.mktmpdir, "seen")
      editor_path = fake_editor_script(%(cat "$1" > "#{seen}"))
      editor = described_class.new(command: editor_path)

      editor.edit(content: "the-seed-manifest", path: buffer_path)

      expect(File.read(seen)).to eq("the-seed-manifest")
    end

    it "splits a command with arguments into argv (e.g. `code --wait`)" do
      # The script records its own arguments; we assert the flag survived the
      # split and the buffer path was appended as the final argument.
      args_file = File.join(Dir.mktmpdir, "args")
      editor_path = fake_editor_script(%(printf '%s\\n' "$@" > "#{args_file}"))
      editor = described_class.new(command: "#{editor_path} --wait --new-window")

      editor.edit(content: "x", path: buffer_path)

      recorded = File.read(args_file).split("\n")
      expect(recorded).to eq(["--wait", "--new-window", buffer_path])
    end

    it "does not create or delete the path (SecureWorkspace owns its lifecycle)" do
      editor_path = fake_editor_script(":") # no-op editor
      editor = described_class.new(command: editor_path)

      editor.edit(content: "stays", path: buffer_path)

      # Still present after edit -- Editor must never unlink it.
      expect(File).to exist(buffer_path)
    end

    it "raises EditorError before writing the seed when no editor is configured" do
      editor = described_class.new

      with_env("VISUAL" => nil, "EDITOR" => nil) do
        expect { editor.edit(content: "secret-seed", path: buffer_path) }
          .to raise_error(RKSeal::EditorError)
      end

      # Fail-fast guarantee: the secret seed never touched the buffer.
      expect(File).not_to exist(buffer_path)
    end

    it "raises EditorError when the editor command cannot be launched" do
      editor = described_class.new(command: "/nonexistent/editor-binary-xyz")

      expect { editor.edit(content: "x", path: buffer_path) }
        .to raise_error(RKSeal::EditorError, /command not found|could not launch/)
    end

    it "raises EditorError when the editor exits non-zero (aborted edit)" do
      editor_path = fake_editor_script("exit 3")
      editor = described_class.new(command: editor_path)

      expect { editor.edit(content: "x", path: buffer_path) }
        .to raise_error(RKSeal::EditorError, /status 3|aborted/)
    end

    it "raises EditorError when the editor is killed by a signal" do
      # Send ourselves SIGTERM from inside the fake editor.
      editor_path = fake_editor_script("kill -TERM $$")
      editor = described_class.new(command: editor_path)

      expect { editor.edit(content: "x", path: buffer_path) }
        .to raise_error(RKSeal::EditorError, /killed by signal|aborting/)
    end

    it "does not echo the buffer content into the raised error message" do
      editor_path = fake_editor_script("exit 1")
      editor = described_class.new(command: editor_path)

      expect { editor.edit(content: "SUPER-SECRET-PLAINTEXT", path: buffer_path) }
        .to raise_error(RKSeal::EditorError) { |e| expect(e.message).not_to include("SUPER-SECRET") }
    end

    it "injects -n -i NONE for the vim family so swap/viminfo never hit disk" do
      args_file = File.join(Dir.mktmpdir, "args")
      vim = fake_editor_named("vim", %(printf '%s\\n' "$@" > "#{args_file}"))
      editor = described_class.new(command: vim)

      editor.edit(content: "x", path: buffer_path)

      expect(File.read(args_file).split("\n")).to eq(["-n", "-i", "NONE", buffer_path])
    end

    it "does not duplicate a hardening flag the operator already set" do
      args_file = File.join(Dir.mktmpdir, "args")
      vim = fake_editor_named("vim", %(printf '%s\\n' "$@" > "#{args_file}"))
      editor = described_class.new(command: "#{vim} -n")

      editor.edit(content: "x", path: buffer_path)

      # -n is left as the operator placed it; only the missing -i NONE is added.
      expect(File.read(args_file).split("\n")).to eq(["-i", "NONE", "-n", buffer_path])
    end

    it "leaves a non-vim editor (e.g. nano) untouched" do
      args_file = File.join(Dir.mktmpdir, "args")
      nano = fake_editor_named("nano", %(printf '%s\\n' "$@" > "#{args_file}"))
      editor = described_class.new(command: nano)

      editor.edit(content: "x", path: buffer_path)

      expect(File.read(args_file).split("\n")).to eq([buffer_path])
    end
  end

  # Minimal scoped-ENV helper so the suite stays dependency-free (no
  # climate_control gem): set keys for the block, restore afterwards. A nil
  # value deletes the key for the duration.
  def with_env(env)
    original = env.keys.to_h { |key| [key, ENV.fetch(key, nil)] }
    env.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
    yield
  ensure
    original.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end
end
