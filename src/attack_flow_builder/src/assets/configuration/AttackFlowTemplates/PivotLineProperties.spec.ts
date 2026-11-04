import { describe, expect, it } from "vitest";
import { AttackFlow, AttackFlowObjects, BaseObjects } from "./index";
import { Block, DiagramModelFile, DiagramObjectFactory, Line, StringProperty } from "@OpenChart/DiagramModel";

function buildFactory(): DiagramObjectFactory {
    return new DiagramObjectFactory({
        id: "attack_flow_v2",
        canvas: AttackFlow,
        templates: [...AttackFlowObjects, ...BaseObjects]
    });
}

/**
 * Find the exported `dynamic_line` and return its property pairs by id.
 */
function lineProperties(file: DiagramModelFile): Map<string, unknown> {
    const found = new Map<string, unknown>();
    const visit = (node: unknown) => {
        if (Array.isArray(node)) {
            node.forEach(visit);
        } else if (node && typeof node === "object") {
            const object = node as { id?: string; properties?: unknown };
            if (object.id === "dynamic_line" && Array.isArray(object.properties)) {
                for (const [key, value] of object.properties as [string, unknown][]) {
                    found.set(key, value);
                }
            }
            Object.values(node).forEach(visit);
        }
    };
    visit(file.toExport());
    return found;
}

describe("ATT&CK-pivot line properties", () => {
    it("keeps x_order_basis and x_evidence_quote through export and re-import", () => {
        const factory = buildFactory();
        const file = new DiagramModelFile(factory);
        const src = factory.createNewDiagramObject("action", Block);
        const dst = factory.createNewDiagramObject("action", Block);
        file.canvas.addObject(src);
        file.canvas.addObject(dst);
        const line = factory.createNewDiagramObject("dynamic_line", Line);
        line.source.link(src.anchors.values().next().value!);
        line.target.link(dst.anchors.values().next().value!);
        line.properties.get("x_order_basis", StringProperty)!.setValue("explicit");
        line.properties.get("x_evidence_quote", StringProperty)!.setValue("then they moved laterally");
        file.canvas.addObject(line);

        const first = lineProperties(file);
        expect(first.get("x_order_basis")).toBe("explicit");
        expect(first.get("x_evidence_quote")).toBe("then they moved laterally");

        // Open and save again, as the Builder does with an API-generated .afb.
        const reopened = new DiagramModelFile(factory, file.toExport());
        const second = lineProperties(reopened);
        expect(second.get("x_order_basis")).toBe("explicit");
        expect(second.get("x_evidence_quote")).toBe("then they moved laterally");
    });
});
