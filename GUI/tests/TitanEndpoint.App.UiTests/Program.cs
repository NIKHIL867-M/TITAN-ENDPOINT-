using TitanEndpoint.App.UiTests;

// FORU.TXT 0.8: "Create GUI\tests\TitanEndpoint.App.UiTests\ as a real Windows UI Automation
// project and add it to GUI\TitanEndpoint.sln." Matches the existing
// GUI\tests\TitanEndpoint.Core.RegressionTests\Program.cs convention: a plain console harness that
// accumulates named pass/fail results rather than depending on an external test framework.
//
// Pass one or more suite names on the command line to run a focused regression (case-insensitive),
// or pass no names to run the complete gate. Hardware/long-duration acceptance remains separate.

// Manually-invoked demo, deliberately NOT part of the automated suites[] list below: it starts the
// real fleet against real production settings and leaves the GUI open at the end instead of
// cleaning up, so an operator can inspect real live data on screen. Never runs as part of the
// default full-gate invocation.
if (args.Length > 0 && string.Equals(args[0], "--demo-fleet", StringComparison.OrdinalIgnoreCase))
{
    var seconds = args.Length > 1 && int.TryParse(args[1], out var s) ? s : 120;
    FleetDemo.Run(seconds);
    return 0;
}

var allFailures = new List<string>();

void RunSuite(string name, Func<List<string>> run)
{
    Console.WriteLine($"\n===== {name} =====");
    try
    {
        var failures = run();
        allFailures.AddRange(failures.Select(f => $"{name}: {f}"));
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[SUITE ERROR] {name} threw {ex.GetType().Name}: {ex.Message}");
        allFailures.Add($"{name}: suite threw {ex.GetType().Name}: {ex.Message}");
    }
}

var suites = new (string Name, Func<List<string>> Run)[]
{
    ("ControlFixtureTests", ControlFixtureTests.Run),
    ("NavigationTests", NavigationTests.Run),
    ("EndpointControlTests", EndpointControlTests.Run),
    ("AccessibilityTests", AccessibilityTests.Run),
    ("CustomRuleWorkflowTests", CustomRuleWorkflowTests.Run),
    ("NetworkWorkspaceTests", NetworkWorkspaceTests.Run),
    ("VisualRegressionTests", VisualRegressionTests.Run),
    ("ReliabilityTests", ReliabilityTests.Run),
    ("FullFleetLifecycleTests", FullFleetLifecycleTests.Run),
    ("NetworkLiveCaptureTests", NetworkLiveCaptureTests.Run),
    ("ApplicationLiveTests", ApplicationLiveTests.Run),
    ("CorrelationLiveTests", CorrelationLiveTests.Run),
    ("UnifiedCorrelationSchemaTests", UnifiedCorrelationSchemaTests.Run),
    ("FileLiveTests", FileLiveTests.Run),
    ("PortLiveTests", PortLiveTests.Run),
    ("ProcessLiveTests", ProcessLiveTests.Run),
    ("CustomRuleLiveTests", CustomRuleLiveTests.Run),
    ("CustomRuleProcessCleanupTests", CustomRuleProcessCleanupTests.Run),
    ("FailurePathTests", FailurePathTests.Run),
};

var requested = args.ToHashSet(StringComparer.OrdinalIgnoreCase);
var selected = requested.Count == 0 ? suites : suites.Where(s => requested.Contains(s.Name)).ToArray();
if (selected.Length == 0)
{
    Console.Error.WriteLine($"No matching suite. Available: {string.Join(", ", suites.Select(s => s.Name))}");
    return 2;
}
foreach (var suite in selected) RunSuite(suite.Name, suite.Run);

Console.WriteLine($"\n===== SUMMARY: {allFailures.Count} failure(s) =====");
foreach (var failure in allFailures) Console.WriteLine($"  - {failure}");

return allFailures.Count == 0 ? 0 : 1;
