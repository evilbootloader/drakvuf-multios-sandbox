from ..cape.plugins import RunSignatures

CALL_LOGS = ("libmon.log", "apimon.log")




def cape_analysis(context: PostprocessContext):

    if not any((analysis_dir / name).exists() for name in CALL_LOGS):
        raise RuntimeError(
            "both syscall.log and apimon.log are either empty or non-existent"
        )
    
    malware_pids = None
    if config.analyze_only_malware_pids:
        malware_pids = get_malware_processes(
            inject_path=analysis_dir / "inject.log",
            pstree_path=analysis_dir / "process_tree.json",
        )
   
    calls = []

    for file in CALL_LOGS:
        if not (analysis_dir / file).exists():
            continue

        with (analysis_dir / file).open("r") as f:    
            
            for l in f:
                line = orjson.loads(l)
                if line.get("EventUID") is None:
                    continue
                if malware_pids:
                    if not line["PID"] in malware_pids:
                        continue
                    call = dict()

                    call["id"] = line["EventUID"]
                    call["timestamp"] = line["TimeStamp"]
                    call["thread_id"] = line["TID"]
                    call["api"] = line["Method"]
                    call["status"] = True if line.get("ReturnValue") else False
                    call["return"] = line.get("ReturnValue")
                    call["arguments"] = line.get("Arguments")
                    call["caller"] = line.get("CalledFrom")

                    calls.append(call)
                else:
                    call = dict()

                    call["id"] = line["EventUID"]
                    call["timestamp"] = line["TimeStamp"]
                    call["thread_id"] = line["TID"]
                    call["api"] = line["Method"]
                    call["status"] = True if line.get("ReturnValue") else False
                    call["return"] = line.get("ReturnValue")
                    call["arguments"] = line.get("Arguments")
                    call["caller"] = line.get("CalledFrom")

                    calls.append(call)

    results = dict()
    results["calls"] = calls
    results["statistics"] = {"signatures": []}

    RunSignatures(context.analysis_dir, results).run()

    print(results)