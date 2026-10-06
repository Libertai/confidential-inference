{
  description = "Images for the LibertAI confidential-GPU inference V-PROGRAM";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # The gateway's source. flake.lock pins the commit, and that pin is what
    # makes a rebuild land on a published measurement; build.sh --models-rev
    # overrides it.
    libertai-models = {
      url = "github:Libertai/libertai-models";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, libertai-models }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;

      # One directory per model under ./models, each with a model.json. The
      # same files drive build.sh, so the alias cannot differ between the
      # gateway's config and the image the guest boots.
      models = lib.mapAttrs
        (name: _: builtins.fromJSON (builtins.readFile (./models + "/${name}/model.json")))
        (lib.filterAttrs (_: type: type == "directory") (builtins.readDir ./models));

      # init.sh gives vLLM this port, and the guest has no /etc/hosts, so it has
      # to be an address rather than `localhost`.
      upstream = "http://127.0.0.1:8005";

      # The on-instance gateway: API-key gating, usage reporting, and the
      # /health/<model> endpoint libertai-api probes before it will route here.
      # Its torch/diffusers/kokoro imports are all function-local, so a text
      # model needs none of them -- 243 MB of closure instead of 2+ GB.
      pythonEnv = pkgs.python3.withPackages (ps: with ps; [
        fastapi
        pydantic
        httpx
        cryptography
        uvicorn
        python-dotenv
        python-multipart
      ]);
      pythonClosure = pkgs.closureInfo { rootPaths = [ pythonEnv ]; };

      backendUrl = "https://inference.api.libertai.io";
      # The API key verification key. Public by definition, so baking it into a
      # measured image loses nothing and makes it auditable.
      apiPublicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE2ZFk1cUxsTThWdGp3MXB3MGswWAp5QlJDdUlMaXZZZU9tVTc2S3JGMWRUUmpIbEQ2U3ZCeVYrc1dVOEZ0OWlTOWlGWGhhVWtLWXlxdmV0TEhjMVJrCm05bktUbjJqQUdNeHM1UXl1NEdRWEdzL0dXd1Z2b0l0Rjl5MGV4MWZ2TG1sRnVGV0RqTFhWNlNRZ3Y0SEFtbFgKTFFrOG9KdmFBSUV6MENER3lnQ3BOTGpQS3hRTVlpSU1taHV2N2tIL1dKczlUNXFaUkJYYmVNNVF2YVhqcjRNYQpPblM1My80TFBpZTgzejBCWk13ZEFCNEI4NHFLZnVtMUxPT1Bva0QvWWwrSlNvSm5iZUhEcmtFZHN5TVBRdDNrCmx2aE9WVm0zeEdYdXVoZmVqQXZTTXFwSW53bnFmRFhQVmRheE1QWmNmZXdpdDlvdUo1ZEtyZWJTaGtQaTlFOC8KbHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

      # Every ext4 here feeds a dm-verity root hash that ends up in the SEV-SNP
      # launch measurement, so the bytes must be reproducible or nobody can
      # rebuild and check what we published. Levers: fixed UUID, fixed NON-zero
      # hash_seed (mke2fs treats an all-zero seed as unset and randomises it),
      # SOURCE_DATE_EPOCH, no journal, non-lazy init. fakeroot normalises
      # ownership to 0:0, which would otherwise be the build user's uid and
      # differ between single-user and multi-user Nix installs.
      mkfsFlags = "-b 4096 -U 00000000-0000-0000-0000-000000000000 -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0 -O ^has_journal";

      # The gateway as its own verified volume, for deployments whose runtime
      # image is a vendor container (vLLM) rather than something built here.
      # Putting it in the workload image would mean rebuilding and re-uploading
      # a 23 GB runtime volume to gain a mount point; putting it in a volume of
      # its own leaves the big volumes byte-identical, so they keep their item
      # hashes. It is measured either way: every volume's dm-verity root hash is
      # in the launch measurement.
      #
      # The interpreter's store paths are absolute, so the workload image
      # symlinks /nix here.
      # `upstream` is an address, not a name: the guest gets /etc/resolv.conf
      # from the runtime but no /etc/hosts, so `localhost` has nothing to
      # resolve it and the gateway fails every proxy hop with EAI_AGAIN.
      mkGateway = { alias, upstream }: pkgs.runCommand "gateway-${alias}.ext4"
        {
          nativeBuildInputs = [ pkgs.e2fsprogs pkgs.fakeroot ];
          SOURCE_DATE_EPOCH = "0";
        }
        ''
          printf %s "${apiPublicKey}" | base64 -d > /dev/null ||
            { echo "apiPublicKey is not valid base64"; exit 1; }
          mkdir -p tree/nix/store tree/opt/libertai-models/data tree/bin
          for p in $(cat ${pythonClosure}/store-paths); do cp -a "$p" tree/nix/store/; done
          ln -s ${pythonEnv}/bin/python tree/bin/python
          cp -r ${libertai-models}/src tree/opt/libertai-models/src
          cat > tree/opt/libertai-models/data/${alias}.json <<MODELJSON
          {"id":"${alias}","url":"${upstream}","allowed_paths":["v1/completions","v1/chat/completions","completions","v1/responses","v1/messages"]}
          MODELJSON
          cat > tree/opt/libertai-models/.env <<ENVFILE
          BACKEND_URL=${backendUrl}
          API_PUBLIC_KEY=${apiPublicKey}
          MODELS=${alias}
          ENVFILE
          find tree -exec touch -h -d @0 {} +
          size=$(( $(du -sm tree | cut -f1) * 125 / 100 + 64 ))
          truncate -s ''${size}M $out
          fakeroot sh -c "chown -R 0:0 tree; mkfs.ext4 -q ${mkfsFlags} -d tree $out"
        '';
    in
    {
      # One `gateway-<alias>` per model directory. The alias is the model id
      # clients send; it must also be the key in libertai-api's models.json,
      # which health-checks /health/<alias> and forwards the body unchanged, so
      # a mismatch anywhere reads as "model not configured".
      packages.${system} = lib.mapAttrs'
        (_: model: lib.nameValuePair "gateway-${model.alias}"
          (mkGateway { inherit (model) alias; inherit upstream; }))
        models;
    };
}
